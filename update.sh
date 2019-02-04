#! /usr/bin/env bash

# @author: http://github.com/welladamm/


CERT_NAME="you_domain.com"

LOCAL_DIR=$(cd $(dirname $0); pwd -P)
LOCAL_CERT_DIR="$LE_WORKING_DIR/$CERT_NAME"
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q"
SCP="scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q"


update_cert_for_dsm() {
    local HOST="$1"
    local PORT=${2:-22}
    local USER=${3:-root}
    local REMOTE_SYS_DEFAULT_CERT_DIR="/usr/syno/etc/certificate/system/default"
    echo -e "[$(date)] \033[32m== Ready to update HTTPS certificate on Synology system: $HOST ==\033[0m"
    local REMOTE_CERT_BASE_DIR="/usr/syno/etc/certificate/_archive"
    local REMOTE_DEFAULT_CERT_NAME=$($SSH -p $PORT $USER@$HOST "cat $REMOTE_CERT_BASE_DIR/DEFAULT")
    local REMOTE_DEFAULT_CERT_DIR="$REMOTE_CERT_BASE_DIR/$REMOTE_DEFAULT_CERT_NAME"
    echo -e "[$(date)] \033[32m Remote default cert dir is $REMOTE_DEFAULT_CERT_DIR \033[0m"
    echo -e "[$(date)] \033[32m Copying new certificate to $HOST... \033[0m"

    $SCP -P $PORT $LOCAL_CERT_DIR/fullchain.cer $USER@$HOST:$REMOTE_DEFAULT_CERT_DIR/fullchain.pem >/dev/null 2>&1 && \
        $SCP $LOCAL_CERT_DIR/fullchain.cer $USER@$HOST:$REMOTE_SYS_DEFAULT_CERT_DIR/fullchain.pem >/dev/null 2>&1 && \
        echo -e "[$(date)] \033[32m Copied fullchain.cer \033[0m"

    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.key $USER@$HOST:$REMOTE_DEFAULT_CERT_DIR/privkey.pem  >/dev/null 2>&1 && \
        $SCP $LOCAL_CERT_DIR/$CERT_NAME.key $USER@$HOST:$REMOTE_SYS_DEFAULT_CERT_DIR/privkey.pem >/dev/null 2>&1 && \
        echo -e "[$(date)] \033[32m Copied $CERT_NAME.key \033[0m"

    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.cer $USER@$HOST:$REMOTE_DEFAULT_CERT_DIR/cert.pem  >/dev/null 2>&1 && \
        $SCP $LOCAL_CERT_DIR/$CERT_NAME.cer $USER@$HOST:$REMOTE_SYS_DEFAULT_CERT_DIR/cert.pem  >/dev/null 2>&1 && \
        echo -e "[$(date)] \033[32m Copied $CERT_NAME.cer \033[0m"

    echo -e "[$(date)] \033[32m Done! \033[0m"
    $SSH -p $PORT $USER@$HOST "/usr/syno/sbin/synoservicectl --restart nginx"
    echo -e "[$(date)] \033[32m== HTTPS certificate on $HOST is now renewed & updated! ==\033[0m"
}

update_cert_for_esxi() {
    local HOST="$1"
    local PORT=${2:-22}
    local USER=${3:-root}
    echo -e "[$(date)] \033[32m== Ready to update HTTPS certificate on ESXi system: $HOST ==\033[0m"
    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.key $USER@$HOST:/etc/vmware/ssl/rui.key
    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.cer $USER@$HOST:/etc/vmware/ssl/rui.crt
    $SSH -p $PORT $USER@$HOST "/etc/init.d/hostd restart"
    echo -e "[$(date)] \033[32m== HTTPS certificate on $HOST is now renewed & updated! ==\033[0m"
}

update_cert_for_unifi() {
    local HOST="$1"
    local PORT=${2:-22}
    local USER=${3:-root}
    echo -e "[$(date)] \033[32m== Ready to update HTTPS certificate on Unifi Controller system: $HOST ==\033[0m"
    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.key $USER@$HOST:/tmp/$CERT_NAME.key
    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.cer $USER@$HOST:/tmp/$CERT_NAME.cer
    $SCP -P $PORT $LOCAL_CERT_DIR/fullchain.cer $USER@$HOST:/tmp/$CERT_NAME.chain
    $SSH -p $PORT $USER@$HOST "openssl pkcs12 -export -inkey /tmp/$CERT_NAME.key -in /tmp/$CERT_NAME.cer -certfile /tmp/$CERT_NAME.chain -out /tmp/$CERT_NAME.p12 -name unifi -password pass:temppass"
    $SSH -p $PORT $USER@$HOST "keytool -importkeystore -deststorepass aircontrolenterprise -destkeypass aircontrolenterprise -destkeystore /var/lib/unifi/keystore -srckeystore /tmp/$CERT_NAME.p12 -srcstoretype PKCS12 -srcstorepass temppass -alias unifi -noprompt >/dev/null 2>&1"
    $SSH -p $PORT $USER@$HOST "service unifi restart"
    $SSH -p $PORT $USER@$HOST "rm /tmp/$CERT_NAME.*"
    echo -e "[$(date)] \033[32m== HTTPS certificate on $HOST is now renewed & updated! ==\033[0m"
}

update_cert_for_routeros() {
    local HOST="$1"
    local PORT=${2:-22}
    local USER=${3:-root}
    echo -e "[$(date)] \033[32m== Ready to update HTTPS certificate on RouterOS system: $HOST ==\033[0m"
    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.key $USER@$HOST:$CERT_NAME.key
    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.cer $USER@$HOST:$CERT_NAME.cer
    $SCP -P $PORT $LOCAL_CERT_DIR/ca.cer $USER@$HOST:letsencrypt-ca.cer
    $SSH -p $PORT $USER@$HOST /certificate remove [find name=$CERT_NAME.cer_0]
    $SSH -p $PORT $USER@$HOST /certificate remove [find name=letsencrypt-ca.cer_0]
    $SSH -p $PORT $USER@$HOST /certificate import file-name=$CERT_NAME.cer passphrase=\"\"
    $SSH -p $PORT $USER@$HOST /certificate import file-name=letsencrypt-ca.cer passphrase=\"\"
    $SSH -p $PORT $USER@$HOST /certificate import file-name=$CERT_NAME.key passphrase=\"\"
    $SSH -p $PORT $USER@$HOST /file remove $CERT_NAME.key
    $SSH -p $PORT $USER@$HOST /file remove $CERT_NAME.cer
    $SSH -p $PORT $USER@$HOST /file remove letsencrypt-ca.cer
    $SSH -p $PORT $USER@$HOST /ip service set www-ssl certificate=$CERT_NAME.cer_0
    echo -e "[$(date)] \033[32m== HTTPS certificate on $HOST is now renewed & updated! ==\033[0m"
}

update_cert_for_plex() {
    local HOST="$1"
    local PORT=${2:-22}
    local USER=${3:-root}
    echo -e "[$(date)] \033[32m== Ready to update HTTPS certificate on Plex Server system: $HOST ==\033[0m"
    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.key $USER@$HOST:/tmp/$CERT_NAME.key
    $SCP -P $PORT $LOCAL_CERT_DIR/$CERT_NAME.cer $USER@$HOST:/tmp/$CERT_NAME.cer
    $SCP -P $PORT $LOCAL_CERT_DIR/fullchain.cer $USER@$HOST:/tmp/$CERT_NAME.chain
    $SSH -p $PORT $USER@$HOST "openssl pkcs12 -export -inkey /tmp/$CERT_NAME.key -in /tmp/$CERT_NAME.cer -certfile /tmp/$CERT_NAME.chain -out /etc/$CERT_NAME.p12 -name plex -password pass:temppass"
    $SSH root@$HOST '/usr/syno/sbin/synoservice --restart "pkgctl-Plex Media Server"'
    echo -e "[$(date)] \033[32m== HTTPS certificate on $HOST is now renewed & updated! ==\033[0m"
}


#The default SSH port is 22
#The default SSH username is root.
#You can set custom SSH port or username,
#Example: update_cert_for_routeros 10.0.0.11 1022 admin

update_cert_for_dsm "your_dsm_host"

update_cert_for_esxi "your_esxi_host"

update_cert_for_unifi "your_unifi_controller_host"

update_cert_for_routeros "your_routeros_host"

update_cert_for_plex "your_plex_host"
