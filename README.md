# USB Diagnostic Tool

## Overview
This tool provides a way to diagnose and perform operations on USB devices while ensuring security through whitelisting and user confirmation.

## Directory Structure

## Usage
- To list USB devices: `./usb_diagnostic --list`
- To repair a specific device: `./usb_diagnostic --repair VID:PID`
- To simulate a repair: `./usb_diagnostic --simulate`

## Security Features
- Read-only access to devices by default.
- Whitelisting of devices based on Vendor ID and Product ID.
- User confirmation before performing sensitive operations.
- Logging of all activities to `logs/usb_diag.log`.