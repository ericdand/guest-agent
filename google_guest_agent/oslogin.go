// Copyright 2019 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/guest-agent/google_guest_agent/cfg"
	"github.com/GoogleCloudPlatform/guest-agent/google_guest_agent/events"
	"github.com/GoogleCloudPlatform/guest-agent/google_guest_agent/events/sshtrustedca"
	"github.com/GoogleCloudPlatform/guest-agent/google_guest_agent/run"
	"github.com/GoogleCloudPlatform/guest-agent/google_guest_agent/sshca"
	"github.com/GoogleCloudPlatform/guest-agent/metadata"
	"github.com/GoogleCloudPlatform/guest-logging-go/logger"
)

var (
	googleComment    = "# Added by Google Compute Engine OS Login."
	googleBlockStart = "#### Google OS Login control. Do not edit this section. ####"
	googleBlockEnd   = "#### End Google OS Login control section. ####"
	trustedCAWatcher events.Watcher

	// deprecatedConfigDirectives contains a list of configuration directives (or lines)
	// that we no longer support and should not be considered for updated versions of a
	// given configuration file.
	deprecatedConfigDirectives = map[string][]string{
		"/etc/pam.d/su": {"account    [success=bad ignore=ignore] pam_oslogin_login.so"},
	}
)

type osloginMgr struct{}

// We also read project keys first, letting instance-level keys take
// precedence.
func getOSLoginEnabled(md *metadata.Descriptor) (bool, bool, bool, bool) {
	var enable bool
	if md.Project.Attributes.EnableOSLogin != nil {
		enable = *md.Project.Attributes.EnableOSLogin
	}
	if md.Instance.Attributes.EnableOSLogin != nil {
		enable = *md.Instance.Attributes.EnableOSLogin
	}
	var twofactor bool
	if md.Project.Attributes.TwoFactor != nil {
		twofactor = *md.Project.Attributes.TwoFactor
	}
	if md.Instance.Attributes.TwoFactor != nil {
		twofactor = *md.Instance.Attributes.TwoFactor
	}
	var skey bool
	if md.Project.Attributes.SecurityKey != nil {
		skey = *md.Project.Attributes.SecurityKey
	}
	if md.Instance.Attributes.SecurityKey != nil {
		skey = *md.Instance.Attributes.SecurityKey
	}
	var reqCerts bool
	if md.Project.Attributes.RequireCerts != nil {
		reqCerts = *md.Project.Attributes.RequireCerts
	}
	if md.Instance.Attributes.RequireCerts != nil {
		reqCerts = *md.Instance.Attributes.RequireCerts
	}
	return enable, twofactor, skey, reqCerts
}

func enableDisableOSLoginCertAuth(ctx context.Context) error {
	if newMetadata == nil {
		logger.Infof("Could not enable/disable OSLogin Cert Auth, metadata is not initialized.")
		return nil
	}

	eventManager := events.Get()
	osLoginEnabled, _, _, _ := getOSLoginEnabled(newMetadata)
	if osLoginEnabled {
		if trustedCAWatcher == nil {
			trustedCAWatcher = sshtrustedca.New(sshtrustedca.DefaultPipePath)
			if err := eventManager.AddWatcher(ctx, trustedCAWatcher); err != nil {
				return err
			}
			sshca.Init()
		}
	}

	return nil
}

func (o *osloginMgr) Diff(ctx context.Context) (bool, error) {
	oldEnable, oldTwoFactor, oldSkey, oldReqCerts := getOSLoginEnabled(oldMetadata)
	enable, twofactor, skey, reqCerts := getOSLoginEnabled(newMetadata)
	return oldMetadata.Project.ProjectID == "" ||
		// True on first run or if any value has changed.
		(oldTwoFactor != twofactor) ||
		(oldEnable != enable) ||
		(oldSkey != skey) ||
		(oldReqCerts != reqCerts), nil
}

func (o *osloginMgr) Timeout(ctx context.Context) (bool, error) {
	return false, nil
}

func (o *osloginMgr) Disabled(ctx context.Context) (bool, error) {
	return runtime.GOOS == "windows", nil
}

func (o *osloginMgr) Set(ctx context.Context) error {
	// We need to know if it was previously enabled for the clearing of
	// metadata-based SSH keys.
	oldEnable, _, _, _ := getOSLoginEnabled(oldMetadata)
	enable, twofactor, skey, reqCerts := getOSLoginEnabled(newMetadata)

	cleanupDeprecatedDirectives()

	if enable && !oldEnable {
		logger.Infof("Enabling OS Login")
		newMetadata.Instance.Attributes.SSHKeys = nil
		newMetadata.Project.Attributes.SSHKeys = nil
		(&accountsMgr{}).Set(ctx)
	} else if !enable && oldEnable {
		logger.Infof("Disabling OS Login")
	} else {
		logger.Infof("Not enabling or disabling OS Login; enablement state is already as desired: %v", enable)
		// Idea: could we simply return early here, if there's really nothing to do?
	}

	logger.Debugf("Updating SSH config...")
	if err := writeSSHConfig(enable, twofactor, skey, reqCerts); err != nil {
		logger.Errorf("Error updating SSH config: %v.", err)
	}

	useSssd := sssdNssSocketIsAvailable()
	logger.Debugf("Updating NSS config...")
	if err := writeNSSwitchConfig(enable, useSssd); err != nil {
		logger.Errorf("Error updating NSS config: %v.", err)
	}

	if useSssd {
		logger.Debugf("Updating SSSD config...")
		if err := writeSssdConfig(enable); err != nil {
			logger.Errorf("Error updating SSSD config: %v.", err)
		}
	} else {
		logger.Debugf("SSSD is not available; not editing sssd.conf.")
	}

	logger.Debugf("Updating PAM config...")
	if err := writePAMConfig(enable, twofactor); err != nil {
		logger.Errorf("Error updating PAM config: %v.", err)
	}

	logger.Debugf("Updating group.conf...")
	if err := writeGroupConf(enable); err != nil {
		logger.Errorf("Error updating group.conf: %v.", err)
	}

	for _, svc := range []string{"nscd", "unscd", "systemd-logind", "cron", "crond"} {
		// These services should be restarted if running
		logger.Debugf("systemctl try-restart %s, if it exists", svc)
		if err := systemctlTryRestart(ctx, svc); err != nil {
			logger.Errorf("Error restarting service: %v.", err)
		}
	}

	// SSH should be started if not running, reloaded otherwise.
	for _, svc := range []string{"ssh", "sshd"} {
		logger.Debugf("systemctl reload-or-restart %s, if it exists", svc)
		if err := systemctlReloadOrRestart(ctx, svc); err != nil {
			logger.Errorf("Error reloading service: %v.", err)
		}
	}

	now := fmt.Sprintf("%d", time.Now().Unix())
	mdsClient.WriteGuestAttributes(ctx, "guest-agent/sshable", now)

	if enable {
		logger.Debugf("Creating OS Login dirs, if needed...")
		if err := createOSLoginDirs(ctx); err != nil {
			logger.Errorf("Error creating OS Login directory: %v.", err)
		}

		logger.Debugf("Creating OS Login sudoers config, if needed...")
		if err := createOSLoginSudoersFile(); err != nil {
			logger.Errorf("Error creating OS Login sudoers file: %v.", err)
		}

		// Refresh the NSS cache asynchronously; this can take a while and shouldn't block.
		go func() {
			logger.Debugf("Starting OS Login NSS cache fill asynchronously...")
			if err := run.Quiet(ctx, "google_oslogin_nss_cache"); err != nil {
				logger.Errorf("Error updating NSS cache: %v.", err)
			}
		}()
	}

	return nil
}

func cleanupDeprecatedLines(fpath string, directives []string) error {
	// If the file doesn't exist don't even try updating it.
	stat, err := os.Stat(fpath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat config file: %+v", err)
	}

	data, err := os.ReadFile(fpath)
	if err != nil {
		return fmt.Errorf("failed to read file: %+v", err)
	}

	var updatedLines []string
	var totalLines int

	for _, line := range strings.Split(string(data), "\n") {
		if !slices.Contains(directives, line) {
			updatedLines = append(updatedLines, line)
		}
		totalLines++
	}

	// Don't attempt to update the config file if no lines werer removed/avoided.
	if totalLines == len(updatedLines) {
		return nil
	}

	err = os.WriteFile(fpath, []byte(strings.Join(updatedLines, "\n")+"\n"), stat.Mode())
	if err != nil {
		return fmt.Errorf("failed to update deprecated configuration directives: %+v", err)
	}

	return nil
}

// cleanupDeprecatedDirectives checks if a given configuration line is an old
// configuration that was deprecated and we should not consider it for the updated
// version.
func cleanupDeprecatedDirectives() {
	for k, v := range deprecatedConfigDirectives {
		if err := cleanupDeprecatedLines(k, v); err != nil {
			logger.Errorf("failed to clean up deprecated directives: %+v", err)
		}
	}
}

func filterGoogleLines(contents string) []string {
	var isgoogle, isgoogleblock bool
	var filtered []string
	for _, line := range strings.Split(contents, "\n") {
		switch {
		case strings.Contains(line, googleComment) && !isgoogleblock:
			isgoogle = true
		case strings.Contains(line, googleBlockEnd):
			isgoogleblock = false
			isgoogle = false
		case isgoogleblock, strings.Contains(line, googleBlockStart):
			isgoogleblock = true
		case isgoogle:
			isgoogle = false
		default:
			filtered = append(filtered, line)
		}
	}
	// Unix text files should end with a final "\n"
	// which strings.Split will account for with a terminal ""
	// so we remove that here, to avoid adding more empty lines.
	// But we can't assume that every file does end in a newline,
	// so only remove it if it's empty as expected.
	if len(filtered) > 0 && filtered[len(filtered)-1] == "" {
		filtered = filtered[:len(filtered)-1]
	}
	return filtered
}

func writeConfigFile(path, contents string) error {
	logger.Debugf("writing %s", path)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer closeFile(file)
	file.WriteString(contents)
	return nil
}

func updateSSHConfig(sshConfig string, enable, twofactor, skey, reqCerts bool) string {
	// TODO: this feels like a case for a text/template
	challengeResponseEnable := "ChallengeResponseAuthentication yes"
	authorizedKeysCommand := "AuthorizedKeysCommand /usr/bin/google_authorized_keys"
	if skey {
		authorizedKeysCommand = "AuthorizedKeysCommand /usr/bin/google_authorized_keys_sk"
	}
	if runtime.GOOS == "freebsd" {
		authorizedKeysCommand = "AuthorizedKeysCommand /usr/local/bin/google_authorized_keys"
		if skey {
			authorizedKeysCommand = "AuthorizedKeysCommand /usr/local/bin/google_authorized_keys_sk"
		}
	}
	authorizedKeysUser := "AuthorizedKeysCommandUser root"
	sourcePerUserConfigs := "Include /var/google-users.d/*"
	matchAllAgain := "Match all"

	// Certificate based authentication.
	authorizedPrincipalsCommand := "AuthorizedPrincipalsCommand /usr/bin/google_authorized_principals %u %k"
	authorizedPrincipalsUser := "AuthorizedPrincipalsCommandUser root"
	trustedUserCAKeys := "TrustedUserCAKeys " + sshtrustedca.DefaultPipePath

	twoFactorAuthMethods := "AuthenticationMethods publickey,keyboard-interactive"
	if (osInfo.OS == "rhel" || osInfo.OS == "centos") && osInfo.Version.Major == 6 {
		authorizedKeysUser = "AuthorizedKeysCommandRunAs root"
		twoFactorAuthMethods = "RequiredAuthentications2 publickey,keyboard-interactive"
	}
	matchblock1 := `Match User sa_*`
	matchblock2 := `       AuthenticationMethods publickey`

	filtered := filterGoogleLines(string(sshConfig))

	if enable {
		osLoginBlock := []string{googleBlockStart}

		// Metadata overrides the config file.
		if reqCerts {
			osLoginBlock = append(osLoginBlock, trustedUserCAKeys, authorizedPrincipalsCommand, authorizedPrincipalsUser)
		} else {
			if cfg.Get().OSLogin.CertAuthentication {
				osLoginBlock = append(osLoginBlock, trustedUserCAKeys, authorizedPrincipalsCommand, authorizedPrincipalsUser)
			}
			osLoginBlock = append(osLoginBlock, authorizedKeysCommand, authorizedKeysUser)
		}
		if twofactor {
			osLoginBlock = append(osLoginBlock, twoFactorAuthMethods, challengeResponseEnable)
		}
		osLoginBlock = append(osLoginBlock, sourcePerUserConfigs, matchAllAgain, googleBlockEnd)
		filtered = append(osLoginBlock, filtered...)
		if twofactor {
			filtered = append(filtered, googleBlockStart, matchblock1, matchblock2, googleBlockEnd)
		}
	}

	return strings.Join(filtered, "\n") + "\n"
}

func writeSSHConfig(enable, twofactor, skey, reqCerts bool) error {
	sshConfig, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return err
	}
	proposed := updateSSHConfig(string(sshConfig), enable, twofactor, skey, reqCerts)
	if proposed == string(sshConfig) {
		return nil
	}
	return writeConfigFile("/etc/ssh/sshd_config", proposed)
}

func updateNSSwitchConfig(nsswitch string, enable, useSssd bool) string {
	oslogin := " cache_oslogin oslogin"
	sssd := " sssd"
	var filtered []string
	if enable {
		for _, line := range strings.Split(nsswitch, "\n") {
			if !strings.HasPrefix(line, "passwd:") {
				filtered = append(filtered, line)
				continue
			}

			if runtime.GOOS == "freebsd" {
				line = strings.Replace(line, "compat", "files", 1)
			}

			if useSssd && !strings.Contains(line, sssd) {
				filtered = append(filtered, line+sssd)
			} else if !useSssd && !strings.Contains(line, "oslogin") {
				filtered = append(filtered, line+oslogin)
			} else {
				filtered = append(filtered, line)
			}
		}
	} else {
		for _, line := range strings.Split(string(nsswitch), "\n") {
			if !strings.HasPrefix(line, "passwd:") {
				filtered = append(filtered, line)
				continue
			}

			if runtime.GOOS == "freebsd" {
				line = strings.Replace(line, "compat", "files", 1)
			}

			if strings.Contains(line, "oslogin") {
				filtered = append(filtered, strings.Replace(line, oslogin, "", 1))
			} else if strings.Contains(line, sssd) {
				// TODO should we actually disable SSSD, or only remove OS Login from the SSSD config? Probably just the latter...
				filtered = append(filtered, strings.Replace(line, sssd, "", 1))
			} else {
				filtered = append(filtered, line)
			}
		}
	}

	// No trailing "\n" here because the input nsswitch already has a trailing newline (and so filtered's last element will be the empty string).
	return strings.Join(filtered, "\n")
}

func writeNSSwitchConfig(enable, useSssd bool) error {
	logger.Debugf("Reading NSSwitch config file...")
	nsswitch, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		logger.Warningf("Error reading NSSwitch config file: %v", err)
		return err
	}
	proposed := updateNSSwitchConfig(string(nsswitch), enable, useSssd)
	if proposed == string(nsswitch) {
		logger.Debugf("NSSwitch config file is as expected. No changes needed.")
		return nil
	}
	if enable {
		logger.Debugf("Editing NSSwitch config file to enable OS Login.")
	} else {
		logger.Debugf("Editing NSSwitch config file to disable OS Login.")
	}
	return writeConfigFile("/etc/nsswitch.conf", proposed)
}

func sssdNssSocketIsAvailable() bool {
	// Connection to a Unix socket should usually return immediately, but we set a timeout to
	// guard against a socket stuck in a "zombie" state, where it might accept a connection
	// but never finish the handshake.
	conn, err := net.DialTimeout("unix", "/var/lib/sss/pipes/nss", time.Millisecond*50)
	if err != nil {
		logger.Infof("No SSSD socket available: %v", err)
		return false
	}
	conn.Close()
	return true
}

func updateSssdConfig(contents string, enable bool) string {
	var newContents []string
	if enable {
		inSssdConfigSection := false
		sawOsLoginDomainConfig := false
		for _, line := range strings.Split(contents, "\n") {
			if strings.HasPrefix(line, "[") {
				if line == "[sssd]" {
					inSssdConfigSection = true
				} else {
					inSssdConfigSection = false
				}
				if line == "[domains/google_oslogin]" {
					sawOsLoginDomainConfig = true
				}
				newContents = append(newContents, line)
				continue
			} // else:
			if inSssdConfigSection {
				if strings.HasPrefix(line, "services = ") {
					if strings.Contains(line, "nss") {
						// NSS already enabled.
						newContents = append(newContents, line)
						continue
					} // else:
					services := strings.Split(line, ",")
					services = append(services, "nss")
					newContents = append(newContents, strings.Join(services, ","))
					continue
				} // else:
				if strings.HasPrefix(line, "domains = ") {
					if strings.Contains(line, "google_oslogin") {
						// OS Login domain already set up.
						newContents = append(newContents, line)
						continue
					} // else:
					domains := strings.Split(line, ",")
					domains = append(domains, "google_oslogin")
					newContents = append(newContents, strings.Join(domains, ","))
					continue
				} // else:
			} // else:
			newContents = append(newContents, line)
			continue
		}
		if !sawOsLoginDomainConfig {
			newContents = append(newContents, "[domains/google_oslogin]")
			newContents = append(newContents, "id_provider = proxy")
			newContents = append(newContents, "proxy_lib_name = google_oslogin")
			newContents = append(newContents, "entry_cache_timeout = 300")
			//newContents = append(newContents, "auth_provider = proxy") // This is for PAM only?
			//newContents = append(newContents, "cache_credentials = true")
			newContents = append(newContents, "")
		}
	} else {
		inSssdConfigSection := false
		for _, line := range strings.Split(contents, "\n") {
			if strings.HasPrefix(line, "[") {
				if line == "[sssd]" {
					inSssdConfigSection = true
				} else {
					inSssdConfigSection = false
				}
				newContents = append(newContents, line)
				continue
			}
			// To disable, delist the OS Login domain. Leave everything else in place.
			if inSssdConfigSection && strings.HasPrefix(line, "domains = ") {
				domains := strings.Split(strings.TrimPrefix(line, "domains = "), ",")
				newDomains := make([]string, len(domains))
				for _, d := range domains {
					if d == "google_oslogin" {
						continue
					} else {
						newDomains = append(newDomains, d)
					}
				}
				newContents = append(newContents, "domains = "+strings.Join(newDomains, ","))
				continue
			}
			newContents = append(newContents, line)
			continue
		}
	}
	return strings.Join(newContents, "\n")
}

func writeSssdConfig(enable bool) error {
	logger.Debugf("Reading SSSD config file...")
	sssd, err := os.ReadFile("/etc/sssd/sssd.conf")
	if err != nil {
		logger.Warningf("Error reading SSSD config file: %v", err)
		return err
	}
	newSssdConfig := updateSssdConfig(string(sssd), enable)
	logger.Debugf("Writing SSSD config file...")
	return writeConfigFile("/etc/sssd/sssd.conf", newSssdConfig)
}

func updatePAMsshdPamless(pamsshd string, enable, twofactor bool) string {
	authOSLogin := "auth       [success=done perm_denied=die default=ignore] pam_oslogin_login.so"
	authGroup := "auth       [default=ignore] pam_group.so"
	sessionHomeDir := "session    [success=ok default=ignore] pam_mkhomedir.so"

	if runtime.GOOS == "freebsd" {
		authOSLogin = "auth       optional pam_oslogin_login.so"
		authGroup = "auth       optional pam_group.so"
		sessionHomeDir = "session    optional pam_mkhomedir.so"
	}

	filtered := filterGoogleLines(string(pamsshd))
	if enable {
		topOfFile := []string{googleBlockStart}
		if twofactor {
			topOfFile = append(topOfFile, authOSLogin)
		}
		topOfFile = append(topOfFile, authGroup, googleBlockEnd)
		bottomOfFile := []string{googleBlockStart, sessionHomeDir, googleBlockEnd}
		filtered = append(topOfFile, filtered...)
		filtered = append(filtered, bottomOfFile...)
	}
	return strings.Join(filtered, "\n") + "\n"
}

func writePAMConfig(enable, twofactor bool) error {
	pamsshd, err := os.ReadFile("/etc/pam.d/sshd")
	if err != nil {
		return err
	}

	proposed := updatePAMsshdPamless(string(pamsshd), enable, twofactor)
	if proposed != string(pamsshd) {
		if err := writeConfigFile("/etc/pam.d/sshd", proposed); err != nil {
			return err
		}
	}

	return nil
}

func updateGroupConf(groupconf string, enable bool) string {
	config := "sshd;*;*;Al0000-2400;video"

	filtered := filterGoogleLines(groupconf)
	if enable {
		filtered = append(filtered, []string{googleComment, config}...)
	}

	return strings.Join(filtered, "\n") + "\n"
}

func writeGroupConf(enable bool) error {
	groupconf, err := os.ReadFile("/etc/security/group.conf")
	if err != nil {
		return err
	}
	proposed := updateGroupConf(string(groupconf), enable)
	if proposed != string(groupconf) {
		if err := writeConfigFile("/etc/security/group.conf", proposed); err != nil {
			return err
		}
	}
	return nil
}

// Creates necessary OS Login directories if they don't exist.
func createOSLoginDirs(ctx context.Context) error {
	restorecon, restoreconerr := exec.LookPath("restorecon")

	for _, dir := range []string{"/var/google-sudoers.d", "/var/google-users.d"} {
		err := os.Mkdir(dir, 0750)
		if err != nil {
			if os.IsExist(err) {
				// Double-check permissions.
				s, err := os.Stat(dir)
				if err != nil {
					return err
				}
				// Set permissions to rwxr-x---.
				if s.Mode() != 0750 {
					if err := os.Chmod(dir, 0750); err != nil {
						return err
					}
				}
			} else {
				return err
			}
		}
		if restoreconerr == nil {
			run.Quiet(ctx, restorecon, dir)
		}
	}
	return nil
}

func createOSLoginSudoersFile() error {
	osloginSudoers := "/etc/sudoers.d/google-oslogin"
	if runtime.GOOS == "freebsd" {
		osloginSudoers = "/usr/local" + osloginSudoers
	}
	sudoFile, err := os.OpenFile(osloginSudoers, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0440)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	fmt.Fprintf(sudoFile, "#includedir /var/google-sudoers.d\n")
	return sudoFile.Close()
}

// systemctlTryRestart tries to restart a systemd service if it is already
// running. Stopped services will be ignored.
func systemctlTryRestart(ctx context.Context, servicename string) error {
	if !systemctlUnitExists(ctx, servicename) {
		return nil
	}
	return run.Quiet(ctx, "systemctl", "try-restart", servicename+".service")
}

// systemctlReloadOrRestart tries to reload a running systemd service if
// supported, restart otherwise. Stopped services will be started.
func systemctlReloadOrRestart(ctx context.Context, servicename string) error {
	if !systemctlUnitExists(ctx, servicename) {
		return nil
	}
	return run.Quiet(ctx, "systemctl", "reload-or-restart", servicename+".service")
}

// systemctlStart tries to start a stopped systemd service. Started services
// will be ignored.
func systemctlStart(ctx context.Context, servicename string) error {
	if !systemctlUnitExists(ctx, servicename) {
		return nil
	}
	return run.Quiet(ctx, "systemctl", "start", servicename+".service")
}

func systemctlUnitExists(ctx context.Context, servicename string) bool {
	res := run.WithOutput(ctx, "systemctl", "list-units", "--all", servicename+".service")
	return !strings.Contains(res.StdOut, "0 loaded units listed")
}
