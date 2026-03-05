package xray

import (
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"text/template"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// XrayConfig holds the settings for the xray config template
type XrayConfig struct {
	Port  int
	Users []string // UUIDs
}

const xrayConfigTmpl = `
{
  "log": {
    "loglevel": "warning"
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

var cmd *exec.Cmd

// SyncUsers periodically fetches active users from the DB and restarts Xray if the list changes.
func SyncUsers(pool *pgxpool.Pool, port int) {
	var lastUsers []string
	
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		rows, err := pool.Query(ctx, `
			SELECT u.id
			FROM users u
			JOIN subscriptions s ON u.id = s."userId"
			WHERE s."activeUntil" > NOW() OR s."isLifetime" = true
		`)
		
		if err != nil {
			cancel()
			log.Printf("[Xray] DB query error: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		
		var currentUsers []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				currentUsers = append(currentUsers, id)
			}
		}
		rows.Close()
		cancel()

		// Compare with last users
		changed := false
		if len(currentUsers) != len(lastUsers) {
			changed = true
		} else {
			for i, v := range currentUsers {
				if v != lastUsers[i] {
					changed = true
					break
				}
			}
		}

		if changed {
			log.Printf("[Xray] Active users changed (%d total). Reconfiguring Xray...", len(currentUsers))
			err := restartXray(currentUsers, port)
			if err != nil {
				log.Printf("[Xray] Failed to restart Xray: %v", err)
			} else {
				lastUsers = currentUsers
			}
		}

		time.Sleep(30 * time.Second)
	}
}

func restartXray(users []string, port int) error {
	tmpl, err := template.New("config").Parse(xrayConfigTmpl)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, XrayConfig{
		Port:  port,
		Users: users,
	})
	if err != nil {
		return err
	}

	err = os.WriteFile("xray_config.json", buf.Bytes(), 0644)
	if err != nil {
		return err
	}

	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}

	// Assuming xray binary is in PATH or current directory
	cmd = exec.Command("xray", "run", "-c", "xray_config.json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	err = cmd.Start()
	if err != nil {
		return err
	}
	
	log.Printf("[Xray] Started new xray process with PID %d", cmd.Process.Pid)
	return nil
}
