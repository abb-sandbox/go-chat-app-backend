package chat_handlers

import (
	"context"
	"time"

	"github.com/gorilla/websocket"
)

const (
	pingPeriod = 50 * time.Second // Send pings every 50s
	pongWait   = 60 * time.Second // Expect pongs/messages within 60s
)

type Client struct {
	conn        *websocket.Conn
	sendChannel chan []byte
	handler_ctx context.Context
}

func (c *Client) writePump() {
	defer c.conn.Close()
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	var err error

write_loop:
	for {
		select {
		case message, ok := <-c.sendChannel: // Other functions send data here
			// 1. Check if the channel was closed by another part of your code
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				break write_loop
			}

			err = c.conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				break write_loop
			}
		case <-ticker.C:
			err = c.conn.WriteMessage(websocket.PingMessage, nil)
			if err != nil {
				break write_loop
			}
		case <-c.handler_ctx.Done():
			_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
			break write_loop
		}
	}
}
