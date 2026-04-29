package testutil

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type LinuxServerConfig struct {
	Username string
	Password string
	Services []string
}

type LinuxServer struct {
	Host  string
	ports map[string]int
}

func (s LinuxServer) MappedPort(port string) int { return s.ports[port] }

type ServiceContainer struct {
	Host string
	Port int
}

type MySQLConfig struct {
	Database string
	Username string
	Password string
}

type PostgreSQLConfig struct {
	Database string
	Username string
	Password string
}

type RedisConfig struct {
	Password string
}

type MongoDBConfig struct {
	Username string
	Password string
}

func StartLinuxServer(t *testing.T, cfg LinuxServerConfig) LinuxServer {
	t.Helper()

	t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	ctx := context.Background()
	req := linuxServerRequest(cfg)
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}

	ports := map[string]int{}
	for _, port := range req.ExposedPorts {
		mapped, err := container.MappedPort(ctx, nat.Port(port))
		if err == nil {
			mappedPort, convErr := strconv.Atoi(mapped.Port())
			if convErr == nil {
				ports[port] = mappedPort
			}
		}
	}

	return LinuxServer{Host: host, ports: ports}
}

func StartMySQL(t *testing.T, cfg MySQLConfig) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, mysqlContainerRequest(cfg), "3306/tcp")
}

func mysqlContainerRequest(cfg MySQLConfig) testcontainers.ContainerRequest {
	return testcontainers.ContainerRequest{
		Image:        "mysql:8.4.5",
		ExposedPorts: []string{"3306/tcp"},
		Env: map[string]string{
			"MYSQL_DATABASE":      cfg.Database,
			"MYSQL_USER":          cfg.Username,
			"MYSQL_PASSWORD":      cfg.Password,
			"MYSQL_ROOT_PASSWORD": "root-pass",
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("3306/tcp"),
			// The official MySQL image emits this line during an init-time
			// temporary server start and again after the final server is ready.
			wait.ForLog("ready for connections").WithOccurrence(2),
		).WithStartupTimeout(120 * time.Second),
	}
}

func StartPostgreSQL(t *testing.T, cfg PostgreSQLConfig) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, postgreSQLContainerRequest(cfg), "5432/tcp")
}

func postgreSQLContainerRequest(cfg PostgreSQLConfig) testcontainers.ContainerRequest {
	return testcontainers.ContainerRequest{
		Image:        "postgres:16.8-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_DB":       cfg.Database,
			"POSTGRES_USER":     cfg.Username,
			"POSTGRES_PASSWORD": cfg.Password,
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("5432/tcp"),
			// The official PostgreSQL image logs readiness once for the init-time
			// temporary server and again after the final server starts.
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		).WithStartupTimeout(120 * time.Second),
	}
}

func StartRedis(t *testing.T, cfg RedisConfig) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "redis:7.4.2-alpine",
		ExposedPorts: []string{"6379/tcp"},
		Cmd:          []string{"redis-server", "--requirepass", cfg.Password, "--port", "6379"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("6379/tcp"),
			wait.ForLog("Ready to accept connections"),
		).WithStartupTimeout(60 * time.Second),
	}, "6379/tcp")
}

func StartRedisNoAuth(t *testing.T) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "redis:7.4.2-alpine",
		ExposedPorts: []string{"6379/tcp"},
		Cmd:          []string{"redis-server", "--port", "6379"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("6379/tcp"),
			wait.ForLog("Ready to accept connections"),
		).WithStartupTimeout(60 * time.Second),
	}, "6379/tcp")
}

func StartMongoDBNoAuth(t *testing.T) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "mongo:7.0.16",
		ExposedPorts: []string{"27017/tcp"},
		Cmd:          []string{"mongod", "--bind_ip_all", "--port", "27017"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("27017/tcp"),
			wait.ForLog("Waiting for connections"),
		).WithStartupTimeout(120 * time.Second),
	}, "27017/tcp")
}

func StartMongoDBWithAuth(t *testing.T, cfg MongoDBConfig) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "mongo:7.0.16",
		ExposedPorts: []string{"27017/tcp"},
		Env: map[string]string{
			"MONGO_INITDB_ROOT_USERNAME": cfg.Username,
			"MONGO_INITDB_ROOT_PASSWORD": cfg.Password,
		},
		Cmd: []string{"mongod", "--auth", "--bind_ip_all", "--port", "27017"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("27017/tcp"),
			// The official MongoDB image starts a temporary server to create the
			// root user, then restarts into the final auth-enabled server.
			wait.ForLog("MongoDB init process complete; ready for start up."),
			wait.ForLog("Waiting for connections").WithOccurrence(2),
		).WithStartupTimeout(120 * time.Second),
	}, "27017/tcp")
}

func StartMemcachedNoAuth(t *testing.T) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "memcached:1.6.38-alpine",
		ExposedPorts: []string{"11211/tcp"},
		Cmd:          []string{"memcached", "-m", "64", "-p", "11211", "-u", "memcache", "-vv"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("11211/tcp"),
			wait.ForLog("server listening"),
		).WithStartupTimeout(60 * time.Second),
	}, "11211/tcp")
}

func StartZookeeperNoAuth(t *testing.T) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "zookeeper:3.9.3",
		ExposedPorts: []string{"2181/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("2181/tcp"),
			wait.ForLog("Started AdminServer on address"),
		).WithStartupTimeout(120 * time.Second),
	}, "2181/tcp")
}

func startServiceContainer(t *testing.T, req testcontainers.ContainerRequest, port string) ServiceContainer {
	t.Helper()

	t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}

	mapped, err := container.MappedPort(ctx, nat.Port(port))
	if err != nil {
		t.Fatalf("container mapped port: %v", err)
	}

	mappedPort, err := strconv.Atoi(mapped.Port())
	if err != nil {
		t.Fatalf("convert mapped port: %v", err)
	}

	return ServiceContainer{Host: host, Port: mappedPort}
}

func linuxServerRequest(cfg LinuxServerConfig) testcontainers.ContainerRequest {
	if len(cfg.Services) == 1 && cfg.Services[0] == "ssh" {
		return testcontainers.ContainerRequest{
			Image:        "linuxserver/openssh-server:version-9.7_p1-r4",
			ExposedPorts: []string{"2222/tcp"},
			Env: map[string]string{
				"USER_NAME":       cfg.Username,
				"USER_PASSWORD":   cfg.Password,
				"PASSWORD_ACCESS": "true",
				"SUDO_ACCESS":     "false",
			},
			WaitingFor: wait.ForListeningPort("2222/tcp").WithStartupTimeout(60 * time.Second),
		}
	}

	services := strings.Join(cfg.Services, ",")
	if services == "ftp" {
		return testcontainers.ContainerRequest{
			Image:        "delfer/alpine-ftp-server@sha256:60bb774d8408d9d4d5c74d05d1c086a34ce192c6c1a142ffac268cac0dbc6fac",
			ExposedPorts: []string{"21/tcp"},
			Env: map[string]string{
				"USERS":    fmt.Sprintf("%s|%s|/home/%s|1000", cfg.Username, cfg.Password, cfg.Username),
				"ADDRESS":  "127.0.0.1",
				"SERVICES": services,
			},
			WaitingFor: wait.ForListeningPort("21/tcp").WithStartupTimeout(60 * time.Second),
		}
	}

	return testcontainers.ContainerRequest{
		Image:        "delfer/alpine-ftp-server@sha256:60bb774d8408d9d4d5c74d05d1c086a34ce192c6c1a142ffac268cac0dbc6fac",
		ExposedPorts: []string{"21/tcp"},
		Env: map[string]string{
			"USERS":    fmt.Sprintf("%s|%s", cfg.Username, cfg.Password),
			"ADDRESS":  "127.0.0.1",
			"SERVICES": services,
		},
		WaitingFor: wait.ForListeningPort("21/tcp").WithStartupTimeout(60 * time.Second),
	}
}

type FakeTelnetServer struct {
	Port     int
	attempts atomic.Int32
}

func (s *FakeTelnetServer) Attempts() int {
	return int(s.attempts.Load())
}

func StartFakeTelnet(t *testing.T, username, password string) *FakeTelnetServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen telnet: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	server := &FakeTelnetServer{Port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				server.attempts.Add(1)
				defer c.Close()

				_, _ = fmt.Fprint(c, "login: ")
				buf := make([]byte, 128)
				n, _ := c.Read(buf)
				user := strings.TrimSpace(string(buf[:n]))

				_, _ = fmt.Fprint(c, "Password: ")
				n, _ = c.Read(buf)
				pass := strings.TrimSpace(string(buf[:n]))

				if user == username && pass == password {
					_, _ = fmt.Fprint(c, "Welcome\n")
					return
				}

				_, _ = fmt.Fprint(c, "Login incorrect\n")
			}(conn)
		}
	}()

	return server
}
