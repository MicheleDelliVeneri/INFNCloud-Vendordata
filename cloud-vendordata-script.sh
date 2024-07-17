#!/bin/bash                                                                                                           
export SSH_CONFIG=/etc/ssh/sshd_config
export CIPHERS="Ciphers aes128-ctr,aes128-gcm@openssh.com,aes192-ctr,aes256-ctr,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"
export KEXALGOS="KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1"
export MACS="MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
REDHAT_FOLDER="/etc/redhat-release"
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export instance_id="`cat /var/lib/cloud/data/instance-id`"
export LOGSERVER="vm-central-logging.internal-services.cloud.na.infn.it"
if [ -e $REDHAT_FOLDER ]
then
  echo "Distribution is RedHat Based"
  export LINUX_DISTRIBUTION=RedHat
else
  export LINUX_DISTRIBUTION=`lsb_release -si`
  echo "Distribution is $LINUX_DISTRIBUTION"
fi
case $LINUX_DISTRIBUTION in
  RedHat|Ubuntu)
       # Disable system wide macs policy for sshd if is RHEL 9 based distribution
       if [ $LINUX_DISTRIBUTION = "RedHat" ]; then
         echo "Checking if Distribution is RHEL 9"
         if grep -q 9 /etc/redhat-release ; then
           echo "Disabling System Wide Macs Policy"
           if ! grep -q '#MACs' /etc/crypto-policies/back-ends/opensshserver.config ; then
             sed -i 's/^MACs/#MACs/' /etc/crypto-policies/back-ends/opensshserver.config
             logger "SSHD disable system wide macs policy for sshd in RHEL9 based distributions"
           fi
         fi
       fi
       # Disable weak ssh ciphers and KexAlgorithms on RedHat systems and restart ssh if needed
       if ! grep -q "${CIPHERS}" ${SSH_CONFIG}
       then
           sed -i 's/^Ciphers/#Ciphers/' ${SSH_CONFIG}
           echo "${CIPHERS}" >> ${SSH_CONFIG}
           echo "" >> ${SSH_CONFIG}
           pidof sshd && service sshd restart
       fi
       if ! grep -q "${KEXALGOS}" ${SSH_CONFIG}
       then
         sed -i 's/^KexAlgorithms/#KexAlgorithms/' ${SSH_CONFIG}
         echo "${KEXALGOS}" >> ${SSH_CONFIG}
         echo "" >> ${SSH_CONFIG}
        pidof sshd && service sshd restart
       fi
       if ! grep -q "${MACS}" ${SSH_CONFIG}
       then
         sed -i 's/^MACs/#MACs/' ${SSH_CONFIG}
         echo "${MACS}" >> ${SSH_CONFIG}
         echo "" >> ${SSH_CONFIG}
        pidof sshd && service sshd restart
       fi
       logger "Vendor data injected on $LINUX_DISTRIBUTION host"
       echo "Vendor data injected on $LINUX_DISTRIBUTION host"
       ;;
  *)
       logger "$LINUX_DISTRIBUTION not managed by this script"
       echo "$LINUX_DISTRIBUTION not managed by this script"
       ;;
esac

case $LINUX_DISTRIBUTION in
  Ubuntu|Debian)
       echo "\$template CloudFormat, \"%TIMESTAMP% $instance_id %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n\"" > /etc/rsyslog.d/99-ibiscocloud.conf
       echo "*.* @${LOGSERVER};CloudFormat" >> /etc/rsyslog.d/99-ibiscocloud.conf
       # Restart rsyslog if needed
       pidof rsyslogd && service rsyslog restart
       echo "sudo apt update && sudo apt install wget -y"
       logger "Vendor data injected on $LINUX_DISTRIBUTION host"
       ;;
  Scientific)
      # New format. Doesn't work for CentOS6
      # echo "template(name=\"CloudFormat\" type=\"string\" string= \"%TIMESTAMP% $instance_id %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n\")" > /etc/rsyslog.d/99-ibiscocloud.conf
      # Legacy (old) format
       echo "\$template CloudFormat, \"%TIMESTAMP% $instance_id %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n\"" > /etc/rsyslog.d/99-ibiscocloud.conf
       echo "*.* @${LOGSERVER};CloudFormat" >> /etc/rsyslog.d/99-ibiscocloud.conf
       # Restart rsyslog if needed
       echo "yum install wget -y"
       pidof rsyslogd && service rsyslog restart
       ;;
  RedHat)
      # New format. Doesn't work for CentOS6
      # echo "template(name=\"CloudFormat\" type=\"string\" string= \"%TIMESTAMP% $instance_id %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n\")" > /etc/rsyslog.d/99-ibiscocloud.conf
      # Legacy (old) format
       echo "\$template CloudFormat, \"%TIMESTAMP% $instance_id %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n\"" > /etc/rsyslog.d/99-ibiscocloud.conf
       echo "*.* @${LOGSERVER};CloudFormat" >> /etc/rsyslog.d/99-ibiscocloud.conf
       # Restart rsyslog if needed
       pidof rsyslogd && service rsyslog restart
       echo "dnf install wget --assumeyes"
       logger "Vendor data injected on $LINUX_DISTRIBUTION host"
       ;;
  *)
       logger "$LINUX_DISTRIBUTION not managed by this script"
       ;;
esac
