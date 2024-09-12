package state

import "time"

type Configuration struct {
	CacheType string
	Namespace string
	MemcachedConfiguration
	RedisConfiguration
	TTL time.Duration
}

type RedisConfiguration struct {
	Addr     string
	Username string
	Password string
	Database int
}

type MemcachedConfiguration struct {
	Addr string
}
