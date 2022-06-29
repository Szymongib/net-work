package main

import "io"

type TunVInterface struct {
	DeviceType DeviceType
	Name       string
	RWC        io.ReadWriteCloser
}

type Config struct {
	Name       string
	DeviceType DeviceType
	Driver
	PlatformSpecificParams PlatformSpecificParams
	Persist                bool
	Permissions            *DevicePermissions
}

type DeviceType int

const (
	TUN DeviceType = iota
	TAP
)

type Driver int

const (
	MacOSDriverTunTapOSX Driver = iota
	MacOSDriverSystem
)
