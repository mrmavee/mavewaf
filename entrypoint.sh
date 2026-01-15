#!/bin/sh
set -e

TOR_LOG="/var/log/tor.log"
I2P_LOG="/var/log/i2pd.log"

touch $TOR_LOG
chown tor:root $TOR_LOG

echo "[entrypoint] Setting up permissions..."
if [ -d "/var/lib/tor" ]; then
    echo "[entrypoint] Securing Tor permissions..."
    chown -R tor:root /var/lib/tor
    chmod 700 /var/lib/tor
    if [ -d "/var/lib/tor/hidden_service" ]; then
        echo "[entrypoint] Fixing hidden_service permissions..."
        chown -R tor:root /var/lib/tor/hidden_service
        chmod 700 /var/lib/tor/hidden_service
    fi
fi

echo "[entrypoint] Starting Tor..."
su-exec tor sh -c "tor -f /etc/tor/torrc > $TOR_LOG 2>&1" &
TOR_PID=$!

tail -f $TOR_LOG &

echo "[entrypoint] Waiting for Tor to bootstrap..."
timeout=180
count=0
bootstrapped=0

while [ $count -lt $timeout ]; do
    if grep -q "Bootstrapped 100%" $TOR_LOG; then
        echo "[entrypoint] Tor bootstrapped successfully!"
        bootstrapped=1
        break
    fi
    sleep 1
    count=$((count+1))
done

if [ $bootstrapped -eq 0 ]; then
    echo "[entrypoint] WARNING: Tor bootstrap timeout! Check logs."
fi

if [ "$I2P_ENABLED" = "true" ]; then
    echo "[entrypoint] Setting up i2pd..."
    
    if [ -d "/var/lib/i2pd" ]; then
        echo "[entrypoint] Securing i2pd permissions..."
        chown -R i2pd:i2pd /var/lib/i2pd
        chmod 700 /var/lib/i2pd
        find /var/lib/i2pd -name "*.dat" -exec chmod 600 {} \;
        find /var/lib/i2pd -name "*.keys" -exec chmod 600 {} \;
    fi
    if [ ! -d "/var/lib/i2pd/certificates" ] && [ -d "/usr/share/i2pd/certificates" ]; then
        echo "[entrypoint] Missing certificates detected via volume mount. Restoring defaults..."
        mkdir -p /var/lib/i2pd/certificates
        cp -r /usr/share/i2pd/certificates/* /var/lib/i2pd/certificates/
        chown -R i2pd:i2pd /var/lib/i2pd/certificates
        echo "[entrypoint] Certificates restored."
    fi
    
    touch $I2P_LOG
    chown i2pd:i2pd $I2P_LOG
    
    echo "[entrypoint] Starting i2pd..."
    su-exec i2pd sh -c "i2pd --conf=/etc/i2pd/i2pd.conf --tunconf=/etc/i2pd/tunnels.conf --datadir=/var/lib/i2pd > $I2P_LOG 2>&1" &
    
    sleep 3
    if pgrep -x "i2pd" > /dev/null; then
        echo "[entrypoint] i2pd started successfully!"
    else
        echo "[entrypoint] WARNING: i2pd failed to start! Check logs."
    fi
fi

echo "[entrypoint] Starting MaveWAF..."
exec su-exec mavewaf /app/mavewaf
