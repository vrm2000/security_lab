#!/bin/sh
# This is the CLI for IoT device, it has two flags: -f -> time frecuency sending alerts, -s -> how much alerts user wants to send
echo I am the first IoT device

while getopts ":f:s:" opt; do
  case $opt in
    f)
      echo "Frecuency: $OPTARG" >&2
      ;;
    s)
      echo "Size: $OPTARG" >&2
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Running by default mode..." >&2
      echo "Frecuency: 1s, Size: infinite" >&2
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

while getopts ":s:" opt; do
  case $opt in
    s)
      echo "Size: $OPTARG" >&2
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Running by default mode..." >&2
      echo "Frecuency: 1s, Size: infinite" >&2
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done