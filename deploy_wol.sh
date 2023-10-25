#!/bin/bash

cd $(dirname $0)

PRIVATE_KEY="~/.ssh/maas"

scp -i $PRIVATE_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ./wol.service ubuntu@$1:~/.

DEPLOY="sudo mv ~/wol.service /etc/systemd/system/wol.service && sudo systemctl daemon-reload && sudo systemctl enable --now wol.service && sudo ethtool enp0s31f6 && sudo reboot"
ssh ubuntu@$1 -i $PRIVATE_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -t "$DEPLOY"
