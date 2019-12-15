package main

import (
    "bufio"
    "container/list"
    "fmt"
    "net"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/parkerottaway/RTMessenger/colors"
    "github.com/parkerottaway/RTMessenger/util"
)

const (
    CLIENTPORT   = ":32000"
    TIMEOUT_SECS = 300
)

/* Panic if the error is not nil for certain functions. */
func chk(err error) {
    if err != nil {
        panic(err)
    }
}

func main() {

    /* Channel to listen for activity on UDP and return what is read. */
    data := make(chan util.Message)

    /* Channel to pass errors from listening on UDP. */
    errors := make(chan error)

    /* Channel to pass the network information. */
    client := make(chan *net.UDPAddr)

    /* List of all sessions. */
    sessions := list.New()

    /* Build session list from file. */
    buildSessionList(sessions)

    /* List containing all messages sent to the server. */
    history := list.New()

    /* UPDAddr for the server. */
    clientAddr, err := net.ResolveUDPAddr("udp", CLIENTPORT)

    /* Check for error when listening on all IP addresses. */
    chk(err)

    /* Connect to first client. */
    clientConn, err := net.ListenUDP("udp", clientAddr)

    /* Check for error when listening for first client. */
    chk(err)

    /* Close the connection in the event of a panic. */
    defer clientConn.Close()

    /* Keep checking for timeout every second. */
    go func() {

        /* Perform this infinitely. */
        for {

            /* Iterate through each session. */
            for e := sessions.Front(); e != nil; e = e.Next() {

                /* Check if the session is online. */
                if e.Value.(*util.Session).IsOnline {

                    dur := time.Since(e.Value.(*util.Session).LastInteraction).Seconds()

                    /* Check if the client has timed out. */
                    if int(dur) >= TIMEOUT_SECS {

                        /* Take the session offline. */
                        e.Value.(*util.Session).IsOnline = false

                        /* Send the RESET notice, */
                        util.ServerEncodeAndSendMessage(clientConn,
                            e.Value.(*util.Session).Addr,
                            util.NewMessage(util.OP_SESSION_RESET,
                                0, 0, 0, ""), sessions)
                    }
                }
            }

            /* Check every second. */
            time.Sleep(1 * time.Second)
        }
    }()

    /* Anonymous func to listen for new packet and send the message to all subscribers. */
    go func(data chan<- util.Message, errors chan<- error, client chan<- *net.UDPAddr) {
        for {
            m, co, err := util.ServerReceiveAndDecodeMessage(clientConn, sessions)
            if err == nil {
                data <- m
                client <- co
            } else {
                errors <- err
            }
        }
    }(data, errors, client)

    /* Listen infinitely for data on UDP. */
    for {
        select {
        case recvMsg := <-data: // Recieved a packet from UDP.

            /* Update time. */
            updateTime(recvMsg.Token, sessions)

            selectOperation(clientConn, <-client, &recvMsg, sessions, history)

        case err := <-errors: // There was an error with packet.
            fmt.Println("Got error...")
            fmt.Printf("error:%+v\n", err)
            break
        }
    }

}

/*
 * Build the full list of all possible sessions that can exist from the text file
 * in the directory.
 *
 * l: Reference to session linked list.
 */
func buildSessionList(l *list.List) {

    /* Token that the session will be assigned. */
    var tok uint32 = 1

    /* Open the file containing all users. */
    file, err := os.Open("users.txt")
    chk(err)
    defer file.Close()

    /* Create a new scanner to read file. */
    scanner := bufio.NewScanner(file)

    /* Session to add to the list. */
    var s *util.Session

    /* Iterate over each line. */
    for scanner.Scan() {

        /* New session pointer to add to the list of session references. */
        s = new(util.Session)

        /* Build each session. */
        s.ClientName = strings.Split(scanner.Text(), "&")[0]
        s.ClientToken = tok
        s.SubscribedTo = list.New()
        s.IsOnline = false
        s.Login = scanner.Text()
        s.Key = nil

        /* Add the session to the session list. */
        l.PushBack(s)

        /* Increase the client token. */
        tok++
    }

    fmt.Println("######## All possible logins ########")
    for e := l.Front(); e != nil; e = e.Next() {
        fmt.Print(e.Value.(*util.Session).Login, "\n")
    }
    fmt.Println("#####################################")

    /* Close file. */
    file.Close()
}

/*
 * Logic to select the appropriate function to send the correct information
 * to the client.
 *
 * c:    UDP connection
 * addr: Address to the client.
 * m:    Message received by the server from the client.
 * l:    Session list holding the status of each client.
 * h:    Message history of all clients.
 */
func selectOperation(c *net.UDPConn, addr *net.UDPAddr, m *util.Message, l *list.List,
    h *list.List) {

    /* Select the appropriate action for the packet received. */
    switch m.Opcode {

    /* Handle login event. */
    case util.OP_LOGIN:
        loginHandler(c, addr, m, l)

    /* Handle subscribe event. */
    case util.OP_SUBSCRIBE:
        subHandler(c, addr, m, l)

    /* Handle unsubscribe event. */
    case util.OP_UNSUBSCRIBE:
        unsubHandler(c, addr, m, l)

    /* Handle post event. */
    case util.OP_POST:
        postHandler(c, addr, m, l, h)

    /* Handle retrieve event. */
    case util.OP_RETRIEVE:
        retrieveHandler(c, addr, m, l, h)

    /* Handle logout event. */
    case util.OP_LOGOUT:
        logoutHandler(c, addr, m, l)

    /* Handle key exchange event. */
    case util.OP_SEND_KEY:
        keyHandler(c, addr, m, l)

    /* Handle spiratic event, where the event is unknown. */
    default:
        spiraticEvent(c, addr, m, l)
    }
}

/* Handle key transaction event. This will never be encrypted since we need the raw key.
 *
 * c:    UDP connection to client.
 * addr: Address to send packet to client.
 * m:    Reference to message that was received.
 * l:    List of all possible sessions.
 */
func keyHandler(c *net.UDPConn, addr *net.UDPAddr, m *util.Message, l *list.List) {

    /* Iterate through session list. */
    for e := l.Front(); e != nil; e = e.Next() {

        /* Find the session matching the token. */
        if (*m).Token == e.Value.(*util.Session).ClientToken {

            e.Value.(*util.Session).Key = []byte((*m).Payload)

            fmt.Printf("Client %s's unique key is: %s%s%s\n", e.Value.(*util.Session).ClientName,
                colors.FG_MAGENTA,
                (*m).Payload, colors.RESET)
        }
    }
}

/*
 * Send a session reset back to the client, since the client sent a packet
 * that was not known, let the client know it needs to reset.
 *
 * c:    UDP connection to client.
 * addr: Address to send packet to client.
 * m:    Reference to message that was received.
 * l:    List of all possible sessions.
 */
func spiraticEvent(c *net.UDPConn, addr *net.UDPAddr, m *util.Message, l *list.List) {

    util.ServerEncodeAndSendMessage(c, addr,
        util.NewMessage(util.OP_SESSION_RESET, 0, (*m).Token, 0, ""), l)

    /* Iterate through session list. */
    for e := l.Front(); e != nil; e = e.Next() {

        /* Find the session matching the token. */
        if (*m).Token == e.Value.(*util.Session).ClientToken {

            e.Value.(*util.Session).IsOnline = false
            e.Value.(*util.Session).Key = nil
        }
    }
}

/*
 * Send the n most recent post by subscribed clients.
 *
 * c:    UDP connection to the client.
 * addr: Address to the client.
 * m:    Reference to the message that was sent by the client.
 * l:    List of all possible sessions.
 * h:    List of all messages sent to the server.
 */
func retrieveHandler(c *net.UDPConn, addr *net.UDPAddr, m *util.Message, l *list.List,
    h *list.List) {

    var key []byte = nil

    /* Iterate through session list. */
    for e := l.Front(); e != nil; e = e.Next() {

        /* Find the key matching the token. */
        if (*m).Token == e.Value.(*util.Session).ClientToken {

            /* Check if a key exists. */
            if e.Value.(*util.Session).Key != nil {

                /* Update temp key var. */
                copy(key, e.Value.(*util.Session).Key)
            }
        }
    }

    /* Check if the client isn't logged in. */
    if (*m).Token == 0 {

        /* Send need to login error to client. */
        util.ServerEncodeAndSendMessage(c, addr,
            util.NewMessage(util.OP_MUST_LOGIN_FIRST_ERR, 0, 0, 0, ""), l)

        return
    }

    counter := 0

    limit, _ := strconv.Atoi((*m).Payload)

    /* Iterate through message list. */
    for e := h.Back(); e != nil && counter < limit; e = e.Prev() {

        /* Check if client is subscribed to the user. */
        if tokenSubscribedToToken((*m).Token, e.Value.(util.Message).Token, l) {
            util.ServerEncodeAndSendMessage(c, addr,
                util.NewMessage(util.OP_RETRIEVE_ACK, 0, 0, 0,
                    e.Value.(util.Message).Payload), l)

            counter++
        }
    }

}

/*
 * Handle the login event.
 *
 * c:    UDP connection to the client.
 * addr: Address to the client.
 * m:    Reference to the message that was sent by the client.
 * l:    List of all possible sessions.
 */
func loginHandler(c *net.UDPConn, addr *net.UDPAddr, m *util.Message, l *list.List) {

    /* Iterate through entire list until found or end. */
    for e := l.Front(); e != nil; e = e.Next() {

        /* Check if the user even exists in the session list. */
        if strings.Compare(e.Value.(*util.Session).ClientName,
            strings.Split((*m).Payload, "&")[0]) == 0 { // User exists

            if strings.Compare(e.Value.(*util.Session).Login, (*m).Payload) == 0 { // Info correct

                /* Send successful login and the token for the client. */
                err := util.ServerEncodeAndSendMessage(c, addr,
                    util.NewMessage(util.OP_SUCCESSFUL_LOGIN_ACK, 0,
                        e.Value.(*util.Session).ClientToken, 0, ""), l)

                if err != nil {
                    fmt.Println(err)
                    return
                }

                e.Value.(*util.Session).IsOnline = true
                e.Value.(*util.Session).Addr = addr
                e.Value.(*util.Session).LastInteraction = time.Now()

                return

            }
        }

    }

    /* Send failed login and empty token to the client. */
    err := util.ServerEncodeAndSendMessage(c, addr, util.NewMessage(util.OP_FAILED_LOGIN_ACK,
        0, 0, 0, ""), nil)

    if err != nil {
        fmt.Println(err)
    }

}

/*
 * Handle the logout event.
 *
 * c:    UDP connection to the client.
 * addr: Address to the client.
 * m:    Reference to the message that was sent by the client.
 * l:    List of all possible sessions.
 */
func logoutHandler(c *net.UDPConn, addr *net.UDPAddr, m *util.Message, l *list.List) {

    /* Iterate through entire list until found or end. */
    for e := l.Front(); e != nil; e = e.Next() {

        /* Check if the user even exists in the session list. */
        if (*m).Token == e.Value.(*util.Session).ClientToken { // User exists

            /* Send successful logout and the token for the client. */
            err := util.ServerEncodeAndSendMessage(c, addr,
                util.NewMessage(util.OP_LOGOUT_ACK, 0,
                    e.Value.(*util.Session).ClientToken, 0, ""), l)

            if err != nil {
                fmt.Println(err)
                return
            }

            e.Value.(*util.Session).IsOnline = false
            e.Value.(*util.Session).Addr = &net.UDPAddr{}
            e.Value.(*util.Session).LastInteraction = time.Now()
            e.Value.(*util.Session).Key = nil

            return

        }

    }

    /* Send failed login and empty token to the client. */
    err := util.ServerEncodeAndSendMessage(c, addr, util.NewMessage(util.OP_FAILED_LOGIN_ACK,
        0, 0, 0, ""), l)

    if err != nil {
        fmt.Println(err)
    }

}

/*
 * Check if the client name exists in the session list.
 *
 * s: Name of the client to find in the session list.
 * l: List that contains all sessions.
 */
func clientNameExists(s string, l *list.List) bool {

    /* Iterate through list, return true if found, false otherwise. */
    for e := l.Front(); e != nil; e = e.Next() {

        /* If found return true. */
        if strings.Compare(e.Value.(*util.Session).ClientName, s) == 0 {

            return true
        }
    }

    return false
}

/*
 * Given a client name, return that client's token.
 *
 * s: Name of the client.
 * l: List of all session references.
 */
func getToken(s string, l *list.List) uint32 {

    /* Iterate through list, return the token of the client name. */
    for e := l.Front(); e != nil; e = e.Next() {

        if strings.Compare(e.Value.(*util.Session).ClientName, s) == 0 {

            return e.Value.(*util.Session).ClientToken
        }
    }

    return 0
}

/*
 * Get the session reference given the token of a session.
 *
 * i: Token you want to find the session for.
 * l: List of all possible sessions.
 */
func getSessionReference(i uint32, l *list.List) *util.Session {

    /* Iterate through list. */
    for e := l.Front(); e != nil; e = e.Next() {

        if e.Value.(*util.Session).ClientToken == i {
            return e.Value.(*util.Session)
        }
    }

    return nil
}

/*
 * Logic to handle a client subscribing to another client.
 *
 * c:    UDP connection to a client.
 * addr: Address to send to client.
 * m:    Reference to message that was most recently sent.
 * l:    List of all sessions.
 */
func subHandler(c *net.UDPConn, addr *net.UDPAddr, m *util.Message, l *list.List) {

    /* If the user does not exist, send error. */
    if !clientNameExists((*m).Payload, l) {

        /* Send sub failed ack to client. */
        util.ServerEncodeAndSendMessage(c, addr,
            util.NewMessage(util.OP_FAILED_UNSUBSCRIBE_ACK, 0, 0, 0, ""), l)
    }

    /* Iterate through the session list to find the session. */
    for e := l.Front(); e != nil; e = e.Next() {

        /* Find the session with the same token as the payload. */
        if e.Value.(*util.Session).ClientToken == getToken((*m).Payload, l) {

            //util.PrintSuccess("Found session")

            e.Value.(*util.Session).SubscribedTo.PushBack(getSessionReference((*m).Token, l))

            /* Send sub ack to client. */
            util.ServerEncodeAndSendMessage(c, addr,
                util.NewMessage(util.OP_SUCCESSFUL_SUBSCRIBE_ACK, 0, 0, 0, ""), l)

            return
        }
    }

    /* Send sub failed ack to client. */
    util.ServerEncodeAndSendMessage(c, addr,
        util.NewMessage(util.OP_FAILED_SUBSCRIBE_ACK, 0, 0, 0, ""), l)

}

/*
 * Logic to handle a client unsubscribing.
 *
 * c:    UDP connection to a client.
 * addr: Address to send to client.
 * m:    Reference to message that was most recently sent.
 * l:    List of all sessions.
 */
func unsubHandler(c *net.UDPConn, addr *net.UDPAddr, m *util.Message, l *list.List) {

    /* If the user does not exist, send error. */
    if !clientNameExists((*m).Payload, l) {

        /* Send sub failed ack to client. */
        util.ServerEncodeAndSendMessage(c, addr,
            util.NewMessage(util.OP_FAILED_UNSUBSCRIBE_ACK, 0, 0, 0, ""), l)
    }

    /* Iterate through the session list to find the session. */
    for e := l.Front(); e != nil; e = e.Next() {

        /* Find the session with the same content as payload. */
        if e.Value.(*util.Session).ClientToken == getToken((*m).Payload, l) {

            //util.PrintSuccess("Found session")

            /* Look through subscribedTo list. */
            for f := e.Value.(*util.Session).SubscribedTo.Front(); f != nil; f = f.Next() {

                /* If that user exists, unsubscribe. */
                if f.Value.(*util.Session).ClientToken == (*m).Token {
                    e.Value.(*util.Session).SubscribedTo.Remove(f) // Remove reference to other session.

                    /* Send sub ack to client. */
                    util.ServerEncodeAndSendMessage(c, addr,
                        util.NewMessage(util.OP_SUCCESSFUL_UNSUBSCRIBE_ACK, 0, 0, 0, ""), l)

                    return
                }
            }
        }
    }

    /* Send sub failed ack to client. */
    util.ServerEncodeAndSendMessage(c, addr,
        util.NewMessage(util.OP_FAILED_UNSUBSCRIBE_ACK, 0, 0, 0, ""), l)

}

/*
 * Handle the post received by the server from a client. Add it to a linked list
 * of messages and return a post acknowledge.
 *
 * c: UDP connection to send back to client.
 * addr: Address to send acknowledgement back to.
 * m: Reference to the message that was sent triggering the event.
 * l: List of all sessions.
 * h: List of all posts to server.
 */
func postHandler(c *net.UDPConn, addr *net.UDPAddr, m *util.Message, l *list.List,
    h *list.List) {

    /* Send back reset if RESET was sent. */
    if (*m).Token != 0 && strings.Compare((*m).Payload, "RESET") == 0 {

        /* Find the session. */
        for e := l.Front(); e != nil; e = e.Next() {
            util.ServerEncodeAndSendMessage(c, e.Value.(*util.Session).Addr,
                util.NewMessage(util.OP_SESSION_RESET, 0, 0,
                    0, ""), l)

            e.Value.(*util.Session).IsOnline = false
            return
        }
    }

    /* Forward to all online subscribers. First find the subscribers.*/
    for e := l.Front(); e != nil; e = e.Next() {

        // Found the session
        if e.Value.(*util.Session).ClientToken == (*m).Token {

            /* Format the payload. */
            post := "<"
            post += e.Value.(*util.Session).ClientName + "> " + (*m).Payload
            (*m).Payload = util.FormatPayload(post)
            (*m).PayloadLen = util.UpdatePayloadLen((*m).Payload)

            /* Iterate through the sessions that are subscribed to them. */
            for f := e.Value.(*util.Session).SubscribedTo.Front(); f != nil; f = f.Next() {

                /* Write to the address, wait for forward response. */

                //fmt.Printf("Address is %+v\n",f.Value.(*Session).addr)
                util.ServerEncodeAndSendMessage(c, f.Value.(*util.Session).Addr,
                    util.NewMessage(util.OP_FORWARD, util.UpdatePayloadLen(post), 0,
                        (*m).MessageID, post), l) // was e.Value.(*util.Session).SubscribedTo
            }

            /* Add formatted message to the history. */
            h.PushBack(*m)

            /* Send post acknowledgement. */
            util.ServerEncodeAndSendMessage(c, addr,
                util.NewMessage(util.OP_POST_ACK, 0, 0, 0, ""), l)

            return
        }
    }

}

/* Check if a is subscribed to b.
 *
 * a: Token in question.
 * b: Token to see if a is subbed to b.
 * l: List of all sessions.
 */
func tokenSubscribedToToken(a uint32, b uint32, l *list.List) bool {

    // Scan the session list.
    for e := l.Front(); e != nil; e = e.Next() {

        // Find the second client.
        if e.Value.(*util.Session).ClientToken == b {

            // Finid the first client in the second client subbed to list.
            for f := e.Value.(*util.Session).SubscribedTo.Front(); f != nil; f = f.Next() {

                // Found it, so return true
                if f.Value.(*util.Session).ClientToken == a {

                    return true
                }
            }
        }
    }

    return false
}

/*
 * Update the time for each session that is logged in and not timed out.
 *
 * u: Token of the session to check.
 * l: List of all sessions possible.
 */
func updateTime(u uint32, l *list.List) {

    /* Find the session for the token. */
    for e := l.Front(); e != nil; e = e.Next() {

        /* Found the session in the list. */
        if e.Value.(*util.Session).ClientToken == u {

            /* Make sure the time is not nil. */
            if e.Value.(*util.Session).IsOnline {

                /* Update the time. */
                e.Value.(*util.Session).LastInteraction = time.Now()
            }
        }
    }
}
