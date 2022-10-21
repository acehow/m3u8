package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type configuration struct {
	Url    string
	Outf   string
	M3u8f  string
	Keystr string
	Iv     string
}

func main() {
	//copy /b F:\f\*.ts E:\f\new.ts
	file, err := os.Open("config.json")
	if err != nil {
		panic("can't find config.json !")
	}
	defer file.Close()
	size := false
	if len(os.Args) > 1 {
		size = true
	}
	decoder := json.NewDecoder(file)
	conf := configuration{}
	err = decoder.Decode(&conf)
	if err != nil {
		panic(err)
	}

	url := conf.Url
	outf := conf.Outf
	keystr := conf.Keystr
	m3u8f := conf.M3u8f
	//if iv set to 0, create []byte{0,0...}
	ivstr := conf.Iv

	pad := "00000"
	f, err := os.Open(m3u8f)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	i := 1
	if size {
		bytenum := 0
		for {
			line, err := rd.ReadString('\n') //以'\n'为结束符读入一行
			if err != nil || io.EOF == err {
				break
			}
			str := strings.Replace(line, "\n", "", -1)
			if strings.HasSuffix(str, "ts") {
				if i == 1 {
					res, err := http.Get(url + str)
					if err != nil {
						panic(err)
					}

					key := []byte(keystr)
					iv := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
					if ivstr !="0"{
						iv =[]byte(ivstr)
					}
					
					body, err := io.ReadAll(res.Body)
					if err != nil {
						fmt.Println(err)
						return
					}

					if keystr != "" {
						result, err := Aes128Decrypt(body, key, iv)
						if err != nil {
							fmt.Println(err.Error())
							return
						}
						bytenum = len(result)
					} else {
						bytenum = len(body)
					}

					res.Body.Close()
				}
				i++
			}
		}
		fmt.Println(bytenum*i/1024/1024, "M")
		os.Exit(0)
	}

	for {
		line, err := rd.ReadString('\n') //以'\n'为结束符读入一行
		if err != nil || io.EOF == err {
			break
		}
		str := strings.Replace(line, "\n", "", -1)
		if strings.HasSuffix(str, "ts") {
			fmt.Println(url + str)
			// download ts file

			res, err := http.Get(url + str)
			if err != nil {
				panic(err)
			}
			// set filename
			s := pad + strconv.Itoa(i)
			fname := s[len(s)-5:]

			key := []byte(keystr)
			iv := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
			if ivstr !="0"{
				iv =[]byte(ivstr)
			}

			body, err := io.ReadAll(res.Body)
			if err != nil {
				fmt.Println(err)
				return
			}

			if keystr != "" {
				result, err := Aes128Decrypt(body, key, iv)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				os.WriteFile(outf+fname+".ts", result, 0666)
			} else {
				os.WriteFile(outf+fname+".ts", body, 0666)
			}

			fmt.Println(fname)
			//io.Copy(f, res.Body)
			res.Body.Close()
			i++
		}
	}

	fmt.Println(`copy /b F:\f\*.ts E:\f\new.ts`)
}

func Aes128Encrypt(origData, key []byte, IV []byte) ([]byte, error) {
	if key == nil || len(key) != 16 {
		return nil, nil
	}
	if IV != nil && len(IV) != 16 {
		return nil, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, IV[:blockSize])
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}
func Aes128Decrypt(crypted, key []byte, IV []byte) ([]byte, error) {
	if key == nil || len(key) != 16 {
		return nil, nil
	}
	if IV != nil && len(IV) != 16 {
		return nil, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, IV[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
