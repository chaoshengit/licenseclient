package licenseclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/wonderivan/logger"
	"io/ioutil"
	"net/http"
	"os"
)

//type dbCli gorm.DB

func (GB *GormDB)RegisterCall(client RegisterBody) (error, CommonResponse) {
	var responseServer CommonResponse
	//var ResponseBody EncryptedBody
	client.ClientID = GenRcodeOnline(client.RegisterCode)
	logger.Info("This is the client id generate at client: ", client.ClientID)
	err2 := GB.RecordID(client.ClientID)
	if err2 != nil {
		logger.Error("Record ID error: ", err2.Error())
		return err2, CommonResponse{}
	}

	clientByte, _ := json.Marshal(client)
	serverIP := os.Getenv("ServerIP")
	url := serverIP + RegisterRequest
	logger.Info("This is the request url: ", url)
	httpClient := &http.Client{}
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	req, err3 := http.NewRequest("POST", url, bytes.NewReader(clientByte))
	if err3 != nil {
		logger.Error("Request error1: ", err3.Error())
		return err3, CommonResponse{}
	}
	serverResponse, err4 := httpClient.Do(req)
	if err4 != nil {
		logger.Error("Request error2: ", err4.Error())
		return err4, CommonResponse{}
	}
	result, err5 := ioutil.ReadAll(serverResponse.Body)
	logger.Debug("This is the online register response data: ", string(result))
	if err5 != nil {
		logger.Error("Request error3: ", err5.Error())
		return err5, CommonResponse{}
	}
	err6 := json.Unmarshal(result, &responseServer)
	if err6 != nil {
		logger.Error("Internal error1: ", err6.Error())
		return err6, CommonResponse{}
	}

	if err8 := RemoveFile(FilePath); err8 != nil {
		logger.Error("Failed to handle the invalid file")
	}
    
	if responseServer.Data == nil {
		logger.Error("Internal error2 ")
		return errors.New("Get plain data error"), CommonResponse{}
	}
	dataRes, _ := responseServer.Data.(map[string]interface{})
	encryptedData, ok1 := dataRes["encrypteddata"].(string)
	sigNature, ok2 := dataRes["signature"].(string)
	if ! ok1 || ! ok2 {
		logger.Error("The element in dataRes is not the corresponding type")
	}
	err9 := GB.UpdateContent(client.ClientID, encryptedData, sigNature)
	if err9 != nil {
	    logger.Error("Internal error3 ")
		return errors.New(ServerInternalError), CommonResponse{}
	}
	logger.Debug("This is the string of the responseServer.Data: ", dataRes)
	err10 := write(responseServer.Data, client)
	if err10 != nil {
		logger.Error("Internal error4 ")
		return errors.New(ServerInternalError), CommonResponse{}
	}
	
	res := GetFileRes(GB)
	if ! res.Value {
		logger.Error("This upload file is in invalid")
		if err4 := RemoveFile(FilePath); err4 != nil {
			logger.Error("Failed to handle the invalid file")
		}
		//This is a rollback logic, need clear the license data in db also.
		if err := GB.RollbackContent(client.ClientID); err != nil {
			return err, CommonResponse{}
		}
	}

	return nil, responseServer
}

func PingCall() string {
	x := "chaoshenis here"
	return x
}

func (GB *GormDB)VerifyCall() CheckRes {
	res := GetFileRes(GB)
	logger.Info("This is the res in Verify: ", res)
	res.RegularCheck = GB.CheckResInDB()
	res.GetResTime = GetCurrentTime()
    return res
}

//for offline, generate the client id for the offline register
func (GB *GormDB)GenClientIDCall(sn SNbody) (error, CommonResponse) {

/*	if ! VerifySN(sn.SN) {
		logger.Info("The SN is invalid")
		return errors.New(ClientRequestError), CommonResponse{}
	}*/
	ClientID := GenRcodeOffline()
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

//for deactivate the license for online and offline scene
//this interface will clear all the local data about license
//will execute 2 action: clear the local table, remove the license file
func (GB *GormDB)DeactivateService() error {
	logger.Info("Begin to deactivate Service")
	if err := GB.ClearTable(); err != nil {
		logger.Error("Clear the data in DB failed: ", err.Error())
		return err
	}
	if err2 := RemoveFile(FilePath); err2 != nil {
		logger.Error("Failed to handle the file, deactivated partially, please check the backend and finish it manually")
		return err2
	}
    logger.Info("End to deactivate Service")
	return nil
}