package server

import "time"

// CloseLatestSession closes the most recent active session for the user+addr pair.
func (s *Server) CloseLatestSession(userID, remoteAddr string) {
	s.sessionMu.Lock()
	connKey := sessionConnKey(userID, remoteAddr)
	list := s.sessionsByConn[connKey]
	if len(list) == 0 {
		s.sessionMu.Unlock()
		return
	}
	sess := list[len(list)-1]
	s.sessionMu.Unlock()
	s.CloseSession(sess)
}

// RecordTraffic updates the most recent active session for a user.
func (s *Server) RecordTraffic(userID string, up, down int64) {
	s.sessionMu.Lock()
	list := s.sessionsByUser[userID]
	if len(list) == 0 {
		s.sessionMu.Unlock()
		return
	}
	sess := list[len(list)-1]
	s.sessionMu.Unlock()

	if up > 0 {
		sess.bytesUp.Add(up)
	}
	if down > 0 {
		sess.bytesDown.Add(down)
	}

	now := time.Now().Unix()
	last := sess.lastTrafficReport.Load()
	if now-last >= 10 && sess.lastTrafficReport.CompareAndSwap(last, now) {
		s.UpdateTraffic(sess)
	}
}

// RecordDomain tracks a destination address for a user.
func (s *Server) RecordDomain(userID, reqAddr string) {
	s.tracker.Record(userID, stripPort(reqAddr), 0)
}

func sessionConnKey(userID, remoteAddr string) string {
	return userID + "|" + remoteAddr
}

func removeSessionByID(list []*session, sessionID string) []*session {
	if len(list) == 0 {
		return list
	}

	result := list[:0]
	for _, sess := range list {
		if sess.id != sessionID {
			result = append(result, sess)
		}
	}
	return result
}
