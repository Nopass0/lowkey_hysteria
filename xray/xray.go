package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"text/template"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
	"hysteria_server/heartbeat"
	"hysteria_server/telemetry"
)

type XrayConfig struct {
	Port  int
	Users []string
}

const xrayConfigTmpl = `
{
  "log": {
    "loglevel": "warning"
  },
  "stats": {},
  "api": {
    "tag": "api",
    "listen": "127.0.0.1:10085",
    "services": [
      "StatsService"
    ]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true,
        "statsUserOnline": true
      }
    }
  },
  "inbounds": [
    {
      "port": {{.Port}},
      "protocol": "vless",
      "settings": {
        "clients": [
          {{range $i, $u := .Users}}{{if $i}},{{end}}
          {
            "id": "{{$u}}",
            "email": "{{$u}}",
            "level": 0,
            "flow": "xtls-rprx-vision"
          }
          {{end}}
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "google.com:443",
          "xver": 0,
          "serverNames": [
            "google.com"
          ],
          "privateKey": "97tkV3UQpZrSOQ2fPe1ZDGUc7Ew7Azibfkgtzc46To0",
          "shortIds": [
            "e12b6c973e573780"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
`

var (
	cmd *exec.Cmd

	trafficStatRe = regexp.MustCompile(`^user>>>(.+?)>>>traffic>>>(uplink|downlink)$`)
	onlineStatRe  = regexp.MustCompile(`^user>>>(.+?)>>>(?:online|connection|connections)$`)
)

func SyncUsers(port int) {
	var lastUsers []string

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		rows, err := db.FindMany(ctx, "subscriptions", voidorm.NewQuery().WhereNode(voidorm.QueryNode{
			OR: []voidorm.QueryNode{
				{Field: "isLifetime", Op: voidorm.Eq, Value: true},
				{Field: "activeUntil", Op: voidorm.Gte, Value: time.Now().UTC()},
			},
		}))
		cancel()
		if err != nil {
			log.Printf("[Xray] Subscription query error: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}

		seen := make(map[string]struct{}, len(rows))
		currentUsers := make([]string, 0, len(rows))
		for _, row := range rows {
			userID := db.AsString(row, "userId")
			if userID == "" {
				continue
			}
			if _, ok := seen[userID]; ok {
				continue
			}
			seen[userID] = struct{}{}
			currentUsers = append(currentUsers, userID)
		}
		sort.Strings(currentUsers)

		if !sameUsers(currentUsers, lastUsers) {
			log.Printf("[Xray] Active users changed (%d total), reconfiguring Xray", len(currentUsers))
			if err := restartXray(currentUsers, port); err != nil {
				log.Printf("[Xray] Failed to restart Xray: %v", err)
			} else {
				lastUsers = currentUsers
			}
		}

		time.Sleep(30 * time.Second)
	}
}

func StartStatsPoller() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats, err := queryStats()
		if err != nil {
			log.Printf("[Xray] Stats query failed: %v", err)
			continue
		}

		type userAgg struct {
			up     int64
			down   int64
			online int64
		}

		perUser := map[string]*userAgg{}
		totalOnline := int64(0)
		sawOnline := false

		for _, item := range stats.Stat {
			if m := trafficStatRe.FindStringSubmatch(item.Name); m != nil {
				userID := m[1]
				dir := m[2]
				if _, ok := perUser[userID]; !ok {
					perUser[userID] = &userAgg{}
				}
				if dir == "uplink" {
					perUser[userID].up = item.IntValue()
				} else {
					perUser[userID].down = item.IntValue()
				}
				continue
			}
			if m := onlineStatRe.FindStringSubmatch(item.Name); m != nil {
				userID := m[1]
				if _, ok := perUser[userID]; !ok {
					perUser[userID] = &userAgg{}
				}
				perUser[userID].online = item.IntValue()
				totalOnline += item.IntValue()
				sawOnline = true
			}
		}

		for userID, agg := range perUser {
			telemetry.ApplyVLESSUserSnapshot(userID, heartbeat.ServerID(), agg.up, agg.down, agg.online)
		}
		if sawOnline {
			telemetry.SetVLESSActive(totalOnline)
		}
	}
}

func sameUsers(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func restartXray(users []string, port int) error {
	tmpl, err := template.New("config").Parse(xrayConfigTmpl)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, XrayConfig{Port: port, Users: users}); err != nil {
		return err
	}
	if err := os.WriteFile("xray_config.json", buf.Bytes(), 0644); err != nil {
		return err
	}

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}

	cmd = exec.Command("xray", "run", "-c", "xray_config.json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}
	log.Printf("[Xray] Started new xray process with PID %d", cmd.Process.Pid)
	return nil
}

type statsResponse struct {
	Stat []statsItem `json:"stat"`
}

type statsItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (s statsItem) IntValue() int64 {
	n, _ := strconv.ParseInt(s.Value, 10, 64)
	return n
}

func queryStats() (*statsResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "xray", "api", "statsquery", "--server=127.0.0.1:10085").Output()
	if err != nil {
		return nil, err
	}

	var resp statsResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
