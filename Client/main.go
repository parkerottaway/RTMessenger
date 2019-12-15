package main

import (
    "bufio"
    "encoding/hex"
    "fmt"
    "net"
    "os"
    "strings"

    "github.com/parkerottaway/RTMessenger/colors"
    "github.com/parkerottaway/RTMessenger/util"
)

const (
    SERVER_ADDRESS = "localhost:32000"
)

func chk(err error) {
    if err != nil {
        panic(err)
    }
}

/* Message counter. */
var msgCount uint32 = 0

/* Main function where program starts. */
func main() {

    var clientKey []byte = nil

    /* Channel containing the result of a keyboard event. */
    keyboardEvent := make(chan string)

    /* Client's unique token, assigned by server after login. */
    var clientToken uint32 = 0

    /* Convert the string representation of IP:Port# to reference to UDPAddr type. */
    serverAddr, err := net.ResolveUDPAddr("udp", SERVER_ADDRESS)

    /*
     * Stop the program and print panic information if program cannot connect to IP
     * and port#.
     */
    chk(err)

    /* Get the UPDConn reference. */
    Conn, err := net.DialUDP("udp", nil, serverAddr)

    /* Check connection to server, */
    chk(err)

    /* If a panic is hit, the server will close. */
    defer Conn.Close()

    /* Routine to listen for network activity. */
    go func(c *net.UDPConn) {

        for {

            msg, _, _ := util.ReceiveAndDecodeMessage(c, clientKey)

            switch msg.Opcode {

            case util.OP_SESSION_RESET:

                /* Print session reset error! */
                util.PrintFailure("Session reset!")

                /* Reset the token. */
                clientToken = 0

                clientKey = nil

            case util.OP_SUCCESSFUL_LOGIN_ACK:

                /* Print post success, */
                util.PrintSuccess("login_ack#successful")

                /* Update token. */
                clientToken = msg.Token

                tmp := util.GenerateCipher()

                m := util.NewMessage(util.OP_SEND_KEY, uint8(len(tmp)),
                    clientToken, 0, hex.EncodeToString(tmp))

                /* Send key to the server. */
                err := util.ClientEncodeAndSendMessage(c, m, clientKey)
                if err != nil {
                    util.PrintFailure("ERROR! CANNOT SEND TO SERVER!")
                    fmt.Println(err)
                }

                /* Update client key with the tmp key. */
                copy(clientKey, tmp)

                fmt.Printf("Client's unique key is: %s%s%s\n", colors.FG_MAGENTA,
                    hex.EncodeToString(tmp), colors.RESET)

            case util.OP_FAILED_LOGIN_ACK:

                /* Print taht there was a login failure. */
                util.PrintFailure("login_ack#failure")

                /* Make sure token is zero. */
                clientToken = 0

                /* Make sure key is nil. */
                clientKey = nil

            case util.OP_POST_ACK:

                /* Print post was successful. */
                util.PrintSuccess("post_ack#successful")

            case util.OP_MUST_LOGIN_FIRST_ERR:

                /* Print error. */
                util.PrintFailure("error#must_login_first")

            case util.OP_SUCCESSFUL_SUBSCRIBE_ACK:

                /* Print sub success. */
                util.PrintSuccess("subscribe_ack#successful")

            case util.OP_FAILED_SUBSCRIBE_ACK:

                /* Print sub failed. */
                util.PrintFailure("subscribe_ack#failure")

            case util.OP_SUCCESSFUL_UNSUBSCRIBE_ACK:

                /* Print unsub success. */
                util.PrintSuccess("unsubscribe_ack#successful")

            case util.OP_FAILED_UNSUBSCRIBE_ACK:

                /* Print unsub failed. */
                util.PrintFailure("unsubscribe_ack#failure")

            case util.OP_FORWARD:

                /* Send back forward ack. */
                fmt.Println(msg.Payload)

            case util.OP_RETRIEVE_ACK:

                /* Print the messages. */
                fmt.Println(msg.Payload)

            case util.OP_LOGOUT_ACK:

                /* Print logout. */
                util.PrintSuccess("logout_ack#success")

                /* Reset token. */
                clientToken = 0
            }
        }

    }(Conn)

    /* Create a reader to get text from keyboard input. */
    reader := bufio.NewReader(os.Stdin)

    /* Routine to listen for keyboard activity. */
    go func(r *bufio.Reader, key chan<- string) {

        for {

            /* Read until there is a newline. */
            input, _ := r.ReadString('\n')

            /* Remove newline character. */
            text := strings.TrimSuffix(input, "\n")

            /* Start processing the input and sending/receiving packets. */
            key <- text

        }
    }(reader, keyboardEvent)

    fmt.Print("What do you want to send to the server? ")

    /* Listen and send indefinitely. */
Loop:
    for {

        select {

        /* Handle keyboard event. */
        case k := <-keyboardEvent:

            /* Check the input. */
            switch {
            case strings.Compare("exit", k) == 0: // Exit the program.

                /* Exit the "infinite" loop, close connection, and exit program. */
                break Loop

            case strings.HasPrefix(k, "login#"): // Login.

                /* Get the username and password components of input. */
                text := strings.TrimPrefix(k, "login#")

                /* Send the login request and handle response. */
                clientLogin(&text, Conn, &clientToken, clientKey)

            case strings.HasPrefix(k, "post#"): // Make a post.

                /* Send post to server. */
                postToServer(strings.TrimPrefix(k, "post#"), Conn, &clientToken, clientKey)

            case strings.HasPrefix(k, "subscribe#"): // Subscribe to other users.

                /* Attemtpt to subscribe. */
                subToUser(strings.TrimPrefix(k, "subscribe#"), Conn, &clientToken, clientKey)

            case strings.HasPrefix(k, "unsubscribe#"):

                /* Attemtpt to subscribe. */
                unsubToUser(strings.TrimPrefix(k, "unsubscribe#"), Conn, &clientToken, clientKey)

            case strings.Compare(k, "logout#") == 0:

                if clientToken == 0 {
                    util.PrintFailure("error#must_login_first")
                } else {

                    /* Send logout. */
                    util.ClientEncodeAndSendMessage(Conn, util.NewMessage(util.OP_LOGOUT,
                        0, clientToken, 0, ""), clientKey)
                }

            case strings.HasPrefix(k, "retrieve#"):

                util.ClientEncodeAndSendMessage(Conn, util.NewMessage(util.OP_RETRIEVE,
                    util.UpdatePayloadLen(strings.TrimPrefix(k, "retrieve#")),
                    clientToken, 0, strings.TrimPrefix(k, "retrieve#")), clientKey)

            default: // Unsupported input format.

                util.ClientEncodeAndSendMessage(Conn, util.NewMessage(util.OP_UNKNOWN,
                    0, clientToken, 0, ""), clientKey)

            }

        } // End of select

    } // End of infinite loop.

    Conn.Close()
}

/*
 * Logic for the client login.
 *
 * s:    String containing <USERNAME>&<PASSWORD>
 * addr: Address of the server.
 * c:    UDP connection.
 * t:    Client's token.
 * key:  Byte slice of the key.
 */
func clientLogin(s *string, c *net.UDPConn, t *uint32, key []byte) {

    /* Message to send. */
    var m util.Message

    /* Update opcode and magic numbers. */
    m.First = uint8('P')
    m.Second = uint8('O')
    m.Opcode = util.OP_LOGIN

    /* Make the payload <USERNAME>&<PASSWORD>. */
    m.Payload = util.FormatPayload(*s)

    /* Update length of payload with the appropriate size. */
    m.PayloadLen = util.UpdatePayloadLen(m.Payload)

    /* Send login to the client and get back message*/
    err := util.ClientEncodeAndSendMessage(c, m, key)
    if err != nil {
        util.PrintFailure("ERROR! CANNOT SEND TO SERVER!")
        fmt.Println(err)
    }
}

/*
 * Logic for the client login. Attempt to subscribe to a client.
 *
 * s:    String containing the post
 * addr: Address of the server.
 * c:    UDP connection.
 * t:    Client's token.
 * key:  Byte slice of the key.
 */
func postToServer(s string, c *net.UDPConn, t *uint32, key []byte) {

    if *t == 0 {
        util.PrintFailure("error#must_login_first")
        return
    }

    /* Message to send. */
    var m util.Message

    /* Update opcode and magic numbers. */
    m.First = uint8('P')
    m.Second = uint8('O')
    m.Opcode = util.OP_POST
    m.Token = *t

    /* Make the payload the post. */
    m.Payload = util.FormatPayload(s)

    /* Update length of payload with the appropriate size. */
    m.PayloadLen = util.UpdatePayloadLen(m.Payload)

    /* Send login to the client and get back message*/
    err := util.ClientEncodeAndSendMessage(c, m, key)
    if err != nil {
        util.PrintFailure("ERROR! CANNOT SEND TO SERVER!")
        fmt.Println(err)
    }
}

/*
 * Logic handling the process of this client subscribing to another
 * user.
 *
 * s:   Name of the user to subscribe to.
 * c:   UDP connection to the server.
 * t:   This client's unique token, assigned by the server.
 * key: Byte slice of the key.
 */
func subToUser(s string, c *net.UDPConn, t *uint32, key []byte) {

    /* If client's token is 0, client is not logged in. */
    if *t == 0 {
        util.PrintFailure("error#must_login_first")
        return
    }

    /* Message to send to the server. */
    var m util.Message

    /* Update opcode and magic numbers. */
    m.First = uint8('P')
    m.Second = uint8('O')
    m.Opcode = util.OP_SUBSCRIBE
    m.Token = *t

    /* Make the payload the post. */
    m.Payload = util.FormatPayload(s)

    /* Update length of payload with the appropriate size. */
    m.PayloadLen = util.UpdatePayloadLen(m.Payload)

    /* Send login to the client and get back message*/
    err := util.ClientEncodeAndSendMessage(c, m, key)
    if err != nil { // Send failed.
        util.PrintFailure("ERROR! CANNOT SEND TO SERVER!")
        fmt.Println(err)
    }
}

/*
 * Logic for sending the unsubscribe request. Send the name of the client
 * to unsubscribe from and attempt to unsubscribe from that client.
 *
 * s:   Name of the client this client wants to unsubscribe from.
 * c:   UDP connection to the server.
 * key: Byte slice of the key.
 */
func unsubToUser(s string, c *net.UDPConn, t *uint32, key []byte) {

    /* If client's token is 0, client is not logged in. */
    if *t == 0 {
        util.PrintFailure("error#must_login_first")
        return
    }

    /* Message to send to the server. */
    var m util.Message

    /* Update opcode and magic numbers. */
    m.First = uint8('P')
    m.Second = uint8('O')
    m.Opcode = util.OP_UNSUBSCRIBE
    m.Token = *t

    /* Make the payload the post. */
    m.Payload = util.FormatPayload(s)

    /* Update length of payload with the appropriate size. */
    m.PayloadLen = util.UpdatePayloadLen(m.Payload)

    /* Send login to the client and get back message*/
    err := util.ClientEncodeAndSendMessage(c, m, key)
    if err != nil { // Send failed.
        util.PrintFailure("ERROR! CANNOT SEND TO SERVER!")
        fmt.Println(err)
    }
}
