package licenseclient

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	//_ "os"
	"errors"
)

/*type DBModel interface {
	TableName() string
}*/

type GormDB struct {
	PgClient *gorm.DB
}


/*
//DBConfig DB config object

type ParamDB struct {
	DBType     string
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBDatabase string
}


//LoadConfigFromEnv Load config from environment variables

func (Param *ParamDB) LoadDBParam() {
	logrus.Println("Load DB parameter begin.")
	Param.DBType = os.Getenv("TYPE")
	Param.DBHost = os.Getenv("HOST")
	Param.DBPort = os.Getenv("PORT")
	Param.DBUser = os.Getenv("USER")
	Param.DBPassword = os.Getenv("PASSWORD")
	Param.DBDatabase = os.Getenv("DATABASE")
	logrus.Println("Load DB parameter end.")
}


func (GB **dbCli) Init(Param *ParamDB) {
	logrus.Info("Begin to init db.")

	addr := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable password=%s",
		Param.DBHost, Param.DBUser, Param.DBDatabase, Param.DBPassword)
	logrus.Info("This is the DB addr %s", addr)
	db, err := gorm.Open(Param.DBType, addr)
	if err != nil {
		logrus.Error("faile to init db: %v", err)
	} else {
		logrus.Info("Succeeded to init db.")
	}

	GB.PgClient = db.Debug()
	//GB.ParamDB = Param
}


func (GB **dbCli) Close() {
	logrus.Info("Begin to close db.")
	GB.PgClient.Close()
	logrus.Info("Succeeded to close db.")
}



func (GB *dbCli) CheckAndCreateTable(table DBModel) {
	ifExist := GB.PgClient.HasTable(table)
	tableName := table.TableName()
	if !ifExist {
		logrus.Info("the table %s is not exist, will create", tableName)
		if err := GB.PgClient.CreateTable(table).Error; err != nil {
			logrus.Error("Failed to create table %s: %v.", tableName, err)
		} else {
			logrus.Info("Succeeded to create table %s.", tableName)
		}
	} else {
		GB.PgClient.AutoMigrate(table)
		logrus.Info("the table %s is exist, will not create", tableName)
	}
}

func (GB *GormDB) CreateTables() {
	logrus.Info("Begin to create tables.")
	GB.CreateTableIfNotExist(IdInfo{})
	logrus.Info("Succeeded to create tables.")
}

func (GB *GormDB) CreateTableIfNotExist(tab DBModel) {
	tableName := tab.TableName()
	logrus.Info("Begin to create table %s if not exits.", tableName)

	var table DBModel
	switch tab.(type) {
	case IdInfo:
		table = IdInfo{}
	default:
		log.Panicf("The table %s is not available.", tableName)
	}
	GB.CheckAndCreateTable(table)
}

func (idinfo IdInfo) TableName() string{
	return "id_infos"
}
*/


//update the idb,idc(last)
func (GB *GormDB) insertCtoDB(ids IdInfo) (err error) {
    if err = GB.PgClient.Create(ids).Error; err != nil {
    	return
	}
	return
}

func (GB *GormDB) updateC(timeString string) (error) {
	var id IdInfo
	var count int64
	if err1 := GB.PgClient.Table("id_infos").Where("used = ?",true).Count(&count).Error;err1 != nil {
		logrus.Println("check the count failed")
		return err1
	}
	if count < 1 {
		return errors.New("no record found error")
	}
	if err := GB.PgClient.First(&id, "used = ?",true).Error; err != nil {
		fmt.Println("here1")
		return err
	}

    tx := GB.PgClient.Begin()
	if err := tx.Model(IdInfo{}).Where("id_a = ?",id.IdA).Update("id_b", id.IdC).Error; err != nil {
	    fmt.Println("here2")
		tx.Rollback()
	    return err
	}
	if err2 := tx.Model(IdInfo{}).Where("id_a = ?",id.IdA).Update("id_c",timeString).Error; err2 != nil{
	    fmt.Println("here3")
		tx.Rollback()
	    return err2
	}
	if err := tx.Commit().Error; err != nil {
	    fmt.Println("here4")
		tx.Rollback()
		return err
	}
	
	return nil
	
    //errTs := GB.PgClient.Transaction(func(trs *gorm.DB) error{
	//	if err1 := trs.Model(IdInfo{}).Where("id_a = ?",id.IdA).Update("id_b", id.IdC).Error; err1 != nil {
	//		fmt.Println("here2")
	//		return err1
	//	}
	//	if err2 := trs.Model(IdInfo{}).Where("id_a = ?",id.IdA).Update("id_c",timeString).Error; err2 != nil{
	//		fmt.Println("here3")
	//		return err2
	//	}
	//	fmt.Println("here4")
    //  return nil
	//})

    //if errTs != nil {
	//	fmt.Println("here5")
    //	return
	//}
	//fmt.Println("here6")
    //return
	
}

func (GB *GormDB) updateResult(result, ida string) (err error) {
    if err = GB.PgClient.Model(IdInfo{}).Where("id_a = ?",ida).Update("id_r",result).Error; err != nil {
    	return
	}
    return
}

func (GB *GormDB) CheckC() (checkRes bool) {
	var count int64
	if err := GB.PgClient.Table("id_infos").Where("used = ?",true).Count(&count).Error;err != nil {
		logrus.Println("check the count failed")
		return false
	}
    if count > 0 {
		logrus.Println("coming here, the count is: ",count)
    	return true
	}
	return false
}

func (GB *GormDB) GetCids() (err error, ids []string) {
	if err = GB.PgClient.Model(IdInfo{}).Pluck("id_a",&ids).Error; err != nil {
		return
	}
	return
}

func (GB *GormDB) GetCRecord() (err error, record IdInfo) {
	if err = GB.PgClient.Where("used = true").First(&record).Error; err != nil {
		return
	}
	return
}

//clear all the data in table
func (GB *GormDB) ClearTable() (err error) {
	if err = GB.PgClient.Delete(IdInfo{}).Error; err != nil {
		fmt.Println("operate data failed")
		return
	}
	return
}

//update the using status of the current license
func (GB *GormDB) UpdateUseState(client string) (error) {
	//GB.PgClient.Transaction(func (trans *gorm.DB) error {
	//if err := GB.PgClient.Model(IdInfo{}).Where("used = true").Update("used","f").Error; err != nil {
	//	return err
	//}
	//if err := GB.PgClient.Model(IdInfo{}).Where("id_a = ? and used = false",client).Update("used","t").Error; err != nil {
	//	return err
	//}
	//return nil
	//})
    //return
	tx := GB.PgClient.Begin()
	if err := tx.Model(IdInfo{}).Where("used = true").Update("used","f").Error; err != nil {
	    tx.Rollback()
	    return err
	}
    if err := tx.Model(IdInfo{}).Where("id_a = ? and used = false",client).Update("used","t").Error; err != nil {
        tx.Rollback()
        return err
    }
    if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return err
	}
    return nil
}

//update the license content when online register or upload the license file in offline scene
func (GB *GormDB) UpdateContent(client, content, sig string) (error) {
    tx := GB.PgClient.Begin()
	if err := tx.Model(IdInfo{}).Where("used = true").Update("used","f").Error; err != nil {
	    tx.Rollback()
	    return err
	}
	if err := tx.Model(IdInfo{}).Where("id_a = ?", client).Update("content",content).Update("sig",sig).Update("used","t").Error; err != nil {
	    tx.Rollback()
		return err
	}
	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return err
	}
	return nil
}

func (GB *GormDB) RollbackContent(client string) (error) {
	if err := GB.PgClient.Model(IdInfo{}).Where("id_a = ?", client).Update("content",BlankString).Update("sig",BlankString).Update("used","f").Error; err != nil {
		logrus.Error("Rollback the content failed")
		return err
	}
	return nil
}