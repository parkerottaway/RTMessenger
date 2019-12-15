package util

import (
    "bytes"
    "container/list"
    "crypto/aes"
    "crypto/cipher"
    "encoding/gob"
    "encoding/hex"
    "errors"
    "fmt"
    random "math/rand"
    "net"
    "time"

    "github.com/parkerottaway/RTMessenger/colors"
)

const (
    OP_SESSION_RESET              = 0x00
    OP_MUST_LOGIN_FIRST_ERR       = 0xF0
    OP_LOGIN                      = 0x10
    OP_SUCCESSFUL_LOGIN_ACK       = 0x80
    OP_FAILED_LOGIN_ACK           = 0x81
    OP_SUBSCRIBE                  = 0x20
    OP_SUCCESSFUL_SUBSCRIBE_ACK   = 0x90
    OP_FAILED_SUBSCRIBE_ACK       = 0x91
    OP_UNSUBSCRIBE                = 0x21
    OP_SUCCESSFUL_UNSUBSCRIBE_ACK = 0xA0
    OP_FAILED_UNSUBSCRIBE_ACK     = 0xA1
    OP_POST                       = 0x30
    OP_POST_ACK                   = 0xB0
    OP_FORWARD                    = 0xB1
    OP_FORWARD_ACK                = 0x31
    OP_RETRIEVE                   = 0x40
    OP_RETRIEVE_ACK               = 0xC0
    OP_END_OF_RETRIEVE_ACK        = 0xC1
    OP_LOGOUT                     = 0x1F
    OP_LOGOUT_ACK                 = 0x8F
    OP_UNKNOWN                    = 0xFF
    OP_SEND_KEY                   = 0xFE

    BUFFER_SIZE = 512
    PAYLOAD_MAX = 255
    paddingByte = 255
)

/* Print the error if there is one. */
func chk(e error) {
    if e != nil {
        fmt.Println(e)
    }
}

/* Packet structure that will be sent back and fourth.  */
type Message struct {
    First      uint8  // First magic number.
    Second     uint8  // Second magic number.
    Opcode     uint8  // Operation code to signal what operation is occuring.
    PayloadLen uint8  // Length of the payload (not necessary since strings can use len()).
    Token      uint32 // Client's unique token.
    MessageID  uint32 // Message number.
    Payload    string // Payload to be sent client -> server or server -> client.
}

// Internal Session struct to manage the states of all sessions.
type Session struct {
    ClientName      string       // Name of the client the session belongs to.
    ClientToken     uint32       // Arbitrary token assigned to this client's session.
    LastInteraction time.Time    // Last time there was a packet from client to server.
    Addr            *net.UDPAddr // Address to send to the right client.
    SubscribedTo    *list.List   // Who is subscribed to the client.
    IsOnline        bool         // Check if the user is online and not timed out.
    Login           string       // Username and password required to log into the session.
    Key             []byte       // Key to encrypt/decrypt messages.
}

/*
 * Decode received message from the client ONLY ON THE SERVER.
 *
 * Parameters:
 * c: UPD Connection.
 * key: Unique AES key to decrypt if len(key) is bigger than 0.
 *
 * Return:
 * util.Message: Message either containing the message received from the socket
 *               or an empty message.
 * *net.UDPAddr: UDP address of client IP and port that sent the message.
 * error:        Error from receiving from the socket or from decoding the Message.
 */
func ServerReceiveAndDecodeMessage(c *net.UDPConn, s *list.List) (Message, *net.UDPAddr, error) {

    /* Temp variable to hold AES key. */
    var key []byte = nil

    /* Buffer to hold message bytes and Message */
    recvBytes := make([]byte, BUFFER_SIZE)
    recvm := Message{}
    decryptBytes := make([]byte, BUFFER_SIZE)

    /* Found length of the packet received. */
    n, clientAddr, err := c.ReadFromUDP(recvBytes[:])

    if err != nil {
        return Message{}, clientAddr, err
    }

    /* Find the session with matching port. */
    for e := s.Front(); e != nil; e = e.Next() {

        /* Only check non-null. */
        if e.Value.(*Session).Addr != nil {

            /* Check ports. */
            if e.Value.(*Session).Addr.Port == clientAddr.Port {

                /* Check if a key exists. */
                if e.Value.(*Session).Key != nil {

                    /* Place the key in the temp 'key' variable. */
                    copy(key, e.Value.(*Session).Key)
                }
            }
        }
    }

    // There is an existing key in the session list and the data is going to be encrypted.
    if len(key) > 0 {

        /* Decrypt the bytes slice. */
        decryptBytes = Decrypt(recvBytes[:n], key)

        /* Create new decoder for the decrypted byte slice. */
        dec := gob.NewDecoder(bytes.NewReader(decryptBytes))

        /* Return empty message with error. */
        if err := dec.Decode(&recvm); err != nil {
            return Message{}, clientAddr, err
        }

    } else { // There is no key and one will arrive soon. Data not encrypted.

        /* Create decoder. */
        dec := gob.NewDecoder(bytes.NewReader(recvBytes[:n]))

        /* Return empty message with error. */
        if err := dec.Decode(&recvm); err != nil {
            return Message{}, clientAddr, err
        }

    }

    /* //Return empty message with error.
    if err := dec.Decode(&recvm); err != nil {
        return Message{}, clientAddr, err
    }*/

    /* Return correct struct, client address, and nil error. */
    return recvm, clientAddr, err
}

/*
 * Decode received message from the client.
 *
 * Parameters:
 * c: UPD Connection.
 * key: Unique AES key to decrypt if len(key) is bigger than 0.
 *
 * Return:
 * util.Message: Message either containing the message received from the socket
 *               or an empty message.
 * *net.UDPAddr: UDP address of client IP and port that sent the message.
 * error:        Error from receiving from the socket or from decoding the Message.
 */
func ReceiveAndDecodeMessage(c *net.UDPConn, key []byte) (Message, *net.UDPAddr, error) {

    /* Buffer to hold message bytes and Message */
    recvBytes := make([]byte, BUFFER_SIZE)
    recvm := Message{}
    decryptBytes := make([]byte, BUFFER_SIZE)

    /* Found length of the packet received. */
    n, clientAddr, err := c.ReadFromUDP(recvBytes[:])

    if err != nil {
        return Message{}, clientAddr, err
    }

    // There is an existing key in the session list and the data is going to be encrypted.
    if len(key) > 0 {

        /* Decrypt the bytes slice. */
        decryptBytes = Decrypt(recvBytes[:n], key)

        /* Create new decoder for the decrypted byte slice. */
        dec := gob.NewDecoder(bytes.NewReader(decryptBytes))

        /* Return empty message with error. */
        if err := dec.Decode(&recvm); err != nil {
            return Message{}, clientAddr, err
        }

    } else { // There is no key and one will arrive soon. Data not encrypted.

        /* Create decoder. */
        dec := gob.NewDecoder(bytes.NewReader(recvBytes[:n]))

        /* Return empty message with error. */
        if err := dec.Decode(&recvm); err != nil {
            return Message{}, clientAddr, err
        }

    }

    /* //Return empty message with error.
    if err := dec.Decode(&recvm); err != nil {
        return Message{}, clientAddr, err
    }*/

    /* Return correct struct, client address, and nil error. */
    return recvm, clientAddr, err
}

/*
 * Server-side function to send a message to a client at addr.
 *
 * c:    UDP connection to clients.
 * addr: Address to send to.
 * m:    Message to send.
 * s:    Reference to session list.
 */
func ServerEncodeAndSendMessage(c *net.UDPConn, addr *net.UDPAddr, m Message, s *list.List) error {

    var key []byte

    /* Byte slice to hold bytes of struct to encode. */
    //sendBuff := make([]byte,BUFFER_SIZE)

    /* Buffer to encode struct. */
    var buff bytes.Buffer

    /* Find the session with matching port. */
    for e := s.Front(); e != nil; e = e.Next() {

        /* Only check non-null. */
        if e.Value.(*Session).Addr != nil {

            /* Check ports. */
            if e.Value.(*Session).Addr.Port == addr.Port {

                /* Check if a key exists. */
                if e.Value.(*Session).Key != nil {

                    /* Place the key in the temp 'key' variable. */
                    copy(key, e.Value.(*Session).Key)
                }
            }
        }
    }

    enc := gob.NewEncoder(&buff)

    /* Check for encoding error. */
    err := enc.Encode(&m)

    /* Display error. */
    if err != nil {
        fmt.Print(colors.FG_RED, "ENCODING FAILED.", colors.RESET, "\n")
        return err
    } else {

        // There is an existing key.
        if len(key) > 0 {

            encmsg, err := Encrypt(key, buff.Bytes())
            _, err = c.WriteToUDP(encmsg[:], addr)

            if err != nil {
                PrintFailure("SENDING WITH UDP FAILED. (ENCRYPTED)")
                return err
            }
        } else { // No existing key.

            _, err = c.WriteToUDP(buff.Bytes(), addr)

            if err != nil {
                return err
            }
        }
    }

    return err
}

/*
 * Client-side function to encode a message struct and send to the server. Message
 * is also encrypted if the client has a token from the server and an encryption key.
 *
 * c:   Connection to server.
 * m:   Message to send.
 * key: Byte slice of AES key.
 */
func ClientEncodeAndSendMessage(c *net.UDPConn, m Message, key []byte) error {

    /* Buffer to encode struct. */
    var buff bytes.Buffer

    /* Create encoder. */
    enc := gob.NewEncoder(&buff)

    /* Check for encoding error. */
    err := enc.Encode(&m)

    if err != nil {
        fmt.Print(colors.FG_RED, "ENCODING FAILED.", colors.RESET, "\n")
        return err
    }

    // If key exists, send encrypted.
    if len(key) > 0 {

        encmsg, err := Encrypt(key, buff.Bytes())

        chk(err)

        _, err = c.Write(encmsg)
    } else { // No key, so don't encrypt.

        _, err = c.Write(buff.Bytes())

        if err != nil {
            fmt.Print(colors.FG_RED, "SENDING WITH UDP FAILED.", colors.RESET, "\n")
            return err
        }
    }

    return err
}

/*
 * If the string is longer than PAYLOAD_MAX, truncate to max string length.
 */
func FormatPayload(s string) string {
    if len(s) > PAYLOAD_MAX {
        return s[:PAYLOAD_MAX]
    }
    return s
}

/*
 * Check the magic numbers and return error if they are different.
 */
func CheckMagicNums(m *Message) error {

    // Verify the two numbers are correct.
    if m.First == 'P' && m.Second == 'O' {
        return nil
    }

    // Return an error that they are different.
    return errors.New("Magic nums different!\n")
}

/*
 * Print the text to terminal window in green.
 */
func PrintSuccess(s string) {
    fmt.Print(colors.FG_GREEN, s, colors.RESET, "\n")
}

/*
 * Print the text to terminal window in red.
 */
func PrintFailure(s string) {
    fmt.Print(colors.FG_RED, s, colors.RESET, "\n")
}

/*
 * Get the correct length of the payload (Using PAYLOAD_MAX as the largest value).
 */
func UpdatePayloadLen(s string) uint8 {
    if len(s) > PAYLOAD_MAX {
        return uint8(PAYLOAD_MAX)
    }
    return uint8(len(s))
}

/*
 * Create and return a new message with all parameters.
 */
func NewMessage(op, length uint8, tok, mID uint32, payload string) Message {
    return Message{First: uint8('P'), Second: uint8('O'), Opcode: op, PayloadLen: length,
        Token: tok, MessageID: mID, Payload: payload}
}

/*
 * Create the 16-byte key. Generated using the Unix time as a seed.
 */
func GenerateCipher() []byte {

    /* Seed using current time for pseudo-random number. */
    random.Seed(time.Now().UnixNano())

    /* Byte slice containing the cypher. */
    k := make([]byte, 16)

    /*
     * Allow each possible byte of the cypher exist between
     * [0,254]. The byte 255 will be used as padding.
     */
    for ii := range k {
        k[ii] = byte(random.Intn(paddingByte))
    }

    /* Return string representation of the key. (Not all characters will be printable) */
    return k
}

/*
 * Take a string and a key in the form of []byte, and return the
 * encrypted string.
 *
 * k: Byte slice of the key.
 * t: Byte slice of the go binary of the struct.
 */
func Encrypt(k []byte, t []byte) ([]byte, error) {

    text := Addpadding(t)
    /* Create block to iterate over []byte of Message. */
    blk, err := aes.NewCipher(k)

    /* Check for error. */
    if err != nil {
        return []byte{byte(0)}, err
    }

    /* Create byte slice with the payload and padding. */
    ciphertext := make([]byte, len(text))

    enc := cipher.NewCBCEncrypter(blk, k)
    enc.CryptBlocks([]byte(ciphertext), []byte(text))

    fmt.Printf("The length of encrypted []byte is %d\n", len(hex.EncodeToString(ciphertext)))

    return ciphertext, err
}

/*
 * Decrypt the raw byte slice using the key. Return the go binary of the struct.
 *
 * k: Byte slice of the key.
 * t: Byte slice of the encrypted data.
 */
func Decrypt(k []byte, t []byte) []byte {

    c, err := aes.NewCipher(k)
    chk(err)

    raw := make([]byte, len(t))

    copy(raw, t)

    dec := cipher.NewCBCDecrypter(c, k)
    dec.CryptBlocks(raw, t)

    var count int = 0

    /* Remove padding. */
    for ii := len(raw) - 1; raw[ii] == byte(paddingByte); ii-- {
        count++
    }

    return raw[:len(raw)-count]
}

/*
 * Add padding to the raw byte slice to be encrypted. Data must be a multiple
 * of the key length (in this case, 16).
 *
 * input: Raw byte slice of the data to be padded.
 */
func Addpadding(input []byte) []byte {

    var temp []byte

    /* Determine the difference between the text len and block size. */
    dif := len(input) % aes.BlockSize

    /* Add padding. */
    if dif != 0 {
        temp = make([]byte, len(input)+aes.BlockSize-dif)
        copy(temp, input)
        copy(temp[len(input):], bytes.Repeat([]byte{byte(paddingByte)}, aes.BlockSize-dif))
        fmt.Printf("The formatted text is %d bytes.\n", len(temp))
        return temp
    }

    return input
}
