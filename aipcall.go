package licenseclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wonderivan/logger"
	"io/ioutil"
	"net/http"
	"os"
)

//type dbCli gorm.DB

func (GB *GormDB)RegisterCall(client RegisterBody) (error,CommonResponse) {
	var responseServer CommonResponse
	//var ResponseBody EncryptedBody
	client.ClientID = GenRcode(client.RegisterCode)
	fmt.Println("This is the client id generate at client: ",client.ClientID)
	err2 := GB.RecordID(client.ClientID)
	if err2 != nil {
		logger.Error("Record ID error: ",err2.Error())
		return err2,CommonResponse{}
	}

	clientByte, _ := json.Marshal(client)
	serverIP := os.Getenv("ServerIP")
	url := serverIP + RegisterRequest
	logger.Info("This is the request url: ",url)
	httpClient := &http.Client{}
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	req, err3 := http.NewRequest("POST",url,bytes.NewReader(clientByte))
	if err3 != nil {
		logger.Error("Request error1: ",err3.Error())
		return err3,CommonResponse{}
	}
	serverResponse, err4 := httpClient.Do(req)
	if err4 != nil {
		logger.Error("Request error2: ",err4.Error())
		return err4,CommonResponse{}
	}
	result, err5 := ioutil.ReadAll(serverResponse.Body)
	fmt.Println("This is the online register response data11111: ",string(result))
	if err5 != nil {
		logger.Error("Request error3: ",err5.Error())
		return err5,CommonResponse{}
	}
	err6 := json.Unmarshal(result, &responseServer)
	if err6 != nil {
		logger.Error("Internal error1: ",err6.Error())
		return err6,CommonResponse{}
	}

	if err8 := RemoveFile(FilePath); err8 != nil {
		logger.Error("Failed to handle the invalid file")
	}

	if responseServer.Data == nil {
		logger.Error("Internal error2 ")
		return errors.New("get plain data error"),CommonResponse{}
	}
	err9 := write(responseServer.Data,client)
	if err9 != nil {
		logger.Error("Internal error3 ")
		return errors.New(ServerInternalError),CommonResponse{}
	}
	
	res := GB.GetFileRes()
	if ! res.Value {
		logger.Error("This upload file is in invalid")
		if err4 := RemoveFile(FilePath); err4 != nil {
			logger.Error("Failed to handle the invalid file")
		}
	}

	return nil, responseServer
}

func PingCall() string {
	x := "chaoshenis here"
	return x
}

func (GB *GormDB)VerifyCall() CheckRes {
	res := GB.GetFileRes()
	fmt.Println("This is the res in Verify: ",res)
	fmt.Println("This is the GB.CheckResInDB(): ",GB.CheckResInDB())
	res.RegularCheck = GB.CheckResInDB()
	res.GetResTime = GetCurrentTime()
	//response := CommonResponse{
	//	Data: res,
	//}
    return res
}

//for offline, generate the client id for the offline register
func (GB *GormDB)GenClientIDCall(sn SNbody) (error,CommonResponse) {

	if ! VerifySN(sn.SN) {
		fmt.Println("The SN is invalid")
		return errors.New(ClientRequestError), CommonResponse{}
		//return
	}
	ClientID := GenRcode(sn.SN)
	err2 := GB.RecordID(ClientID)
	if err2 != nil {
		return err2, CommonResponse{}
	}
	response := CommonResponse{
		Data: ClientID,
	}
    return nil, response
}

//Interface: Delete the license file
func RemoveCall() error {
	isThere, err := PathExists(FilePath)
	if err != nil {
		return err
	}

	if ! isThere {
		logger.Info("The file not exist, no need delete again")
		return errors.New("file not exist error")
	}

	if err := RemoveFile(FilePath); err != nil {
		logger.Error("Remove file error: ", err.Error())
		return err
	}
	return nil
}
