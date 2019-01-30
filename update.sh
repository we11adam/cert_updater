#! /usr/bin/env bash

# @author: http://github.com/welladamm/


CERT_NAME="midway.io"

LOCAL_DIR=$(cd $(dirname $0); pwd -P)
LOCAL_CERT_DIR="$LE_WORKING_DIR/$CERT_NAME"
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q"
SCP="scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q"


update_cert_for_dsm() {
    local HOST="$1"
    local REMOTE_SYS_DEFAULT_CERT_DIR="/usr/syno/etc/certificate/system/default"
    echo "Ready to update HTTPS certificate on Synology system: $HOST"
    local REMOTE_CERT_BASE_DIR="/usr/syno/etc/certificate/_archive"
    local REMOTE_DEFAULT_CERT_NAME=$($SSH root@$HOST "cat $REMOTE_CERT_BASE_DIR/DEFAULT")
    local REMOTE_DEFAULT_CERT_DIR="$REMOTE_CERT_BASE_DIR/$REMOTE_DEFAULT_CERT_NAME"
    echo "Remote default cert dir is $REMOTE_DEFAULT_CERT_DIR"
    echo "Copying new certificate to $HOST..."

    $SCP $LOCAL_CERT_DIR/fullchain.cer root@$HOST:$REMOTE_DEFAULT_CERT_DIR/fullchain.pem >/dev/null 2>&1 && \
        $SCP $LOCAL_CERT_DIR/fullchain.cer root@$HOST:$REMOTE_SYS_DEFAULT_CERT_DIR/fullchain.pem >/dev/null 2>&1 && \
        echo "Copied fullchain.cer"

    $SCP $LOCAL_CERT_DIR/$CERT_NAME.key root@$HOST:$REMOTE_DEFAULT_CERT_DIR/privkey.pem  >/dev/null 2>&1 && \
        $SCP $LOCAL_CERT_DIR/$CERT_NAME.key root@$HOST:$REMOTE_SYS_DEFAULT_CERT_DIR/privkey.pem >/dev/null 2>&1 && \
        echo "Copied $CERT_NAME.key"

    $SCP $LOCAL_CERT_DIR/$CERT_NAME.cer root@$HOST:$REMOTE_DEFAULT_CERT_DIR/cert.pem  >/dev/null 2>&1 && \
        $SCP $LOCAL_CERT_DIR/$CERT_NAME.cer root@$HOST:$REMOTE_SYS_DEFAULT_CERT_DIR/cert.pem  >/dev/null 2>&1 && \
        echo "Copied $CERT_NAME.cer"

    echo "Done!"
    $SSH root@$HOST "/usr/syno/sbin/synoservicectl --restart nginx"
    echo "HTTPS certificate on $HOST is now renewed & updated!"
}

update_cert_for_esxi() {
    local HOST="$1"
    echo "Ready to update HTTPS certificate on ESXi system: $HOST"
    $SCP $LOCAL_CERT_DIR/$CERT_NAME.key root@$HOST:/etc/vmware/ssl/rui.key
    $SCP $LOCAL_CERT_DIR/$CERT_NAME.cer root@$HOST:/etc/vmware/ssl/rui.crt
    $SSH root@$HOST "/etc/init.d/hostd restart"
    echo "HTTPS certificate on $HOST is now renewed & updated!"
}

update_cert_for_unifi() {
    local HOST="$1"
    $SCP $LOCAL_CERT_DIR/$CERT_NAME.key root@$HOST:/tmp/$CERT_NAME.key
    $SCP $LOCAL_CERT_DIR/$CERT_NAME.cer root@$HOST:/tmp/$CERT_NAME.cer
    $SCP $LOCAL_CERT_DIR/fullchain.cer root@$HOST:/tmp/$CERT_NAME.chain
    $SSH root@$HOST "openssl pkcs12 -export -inkey /tmp/$CERT_NAME.key -in /tmp/$CERT_NAME.cer -certfile /tmp/$CERT_NAME.chain -out /tmp/$CERT_NAME.p12 -name unifi -password pass:temppass"
    $SSH root@$HOST "keytool -importkeystore -deststorepass aircontrolenterprise -destkeypass aircontrolenterprise -destkeystore /var/lib/unifi/keystore -srckeystore /tmp/$CERT_NAME.p12 -srcstoretype PKCS12 -srcstorepass temppass -alias unifi -noprompt"
    $SSH root@$HOST "service unifi restart"
    $SSH root@$HOST "rm /tmp/$CERT_NAME.*"
}

update_cert_for_routeros() {
    local HOST="$1"
    local PORT="$2"
    local USER="$3"
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
}

update_cert_for_plex() {
    local HOST="$1"
    $SCP $LOCAL_CERT_DIR/$CERT_NAME.key root@$HOST:/tmp/$CERT_NAME.key
    $SCP $LOCAL_CERT_DIR/$CERT_NAME.cer root@$HOST:/tmp/$CERT_NAME.cer
    $SCP $LOCAL_CERT_DIR/fullchain.cer root@$HOST:/tmp/$CERT_NAME.chain
    $SSH root@$HOST "openssl pkcs12 -export -inkey /tmp/$CERT_NAME.key -in /tmp/$CERT_NAME.cer -certfile /tmp/$CERT_NAME.chain -out /tmp/$CERT_NAME.p12 -name plex -password pass:temppass"
    $SSH root@$HOST '"/var/packages/Plex Media Server/scripts/start-stop-status" restart'
}


update_cert_for_dsm "your_dsm_host"

update_cert_for_esxi "your_esxi_host"

update_cert_for_unifi "your_unifi_controller_host"

update_cert_for_routeros "your_routeros_host" "router_os_ssh_port" "username"

update_cert_for_plex "your_plex_host"


