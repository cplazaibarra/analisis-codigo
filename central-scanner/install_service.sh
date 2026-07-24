#!/bin/bash
# Script de instalación para SCAN-CODE como servicio de sistema global

if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecuta este script como root o usando sudo: sudo bash $0"
  exit 1
fi

echo "1. Copiando archivo de servicio a /etc/systemd/system/..."
cp /home/cplaza/Desarrollo/central-scanner/central-scanner.service /etc/systemd/system/

echo "2. Recargando el demonio systemd..."
systemctl daemon-reload

echo "3. Habilitando servicio central-scanner en el arranque..."
systemctl enable central-scanner.service

echo "4. Iniciando el servicio..."
systemctl start central-scanner.service

echo "5. Comprobando el estado del servicio..."
systemctl status central-scanner.service
