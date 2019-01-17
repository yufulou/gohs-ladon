package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/flier/gohs/hyperscan"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// with sync for resource lock
type scratch struct {
	sync.RWMutex
	s *hyperscan.Scratch
}

var (
	Version  string
	Debug    bool
	Port     int
	FilePath string
	Flag     string
	Scratch  scratch
	Db       hyperscan.BlockDatabase
	Uptime   time.Time
	RegexMap map[int]RegexLine
)

type RequestVal struct{
	Gin *gin.Context
	Vars map[string]interface{}
}

type Response struct {
	Errno int         `json:errno`
	Msg   string      `json:msg`
	Data  interface{} `json:data`
}

type MatchResp struct {
	Line       int		 `json:line`
	Id         int       `json:id`
	From       int       `json:from`
	To         int       `json:to`
	Flags      int       `json:flags`
	Context    string    `json:context`
	RegexLinev RegexLine `json:regexline`
}

type RegexLine struct {
	Expr string
	Data string
}

func main() {
	Version = "0.0.1"
	viper.AutomaticEnv()
	var rootCmd = &cobra.Command{
		Use:     "gohs-ladon",
		Short:   fmt.Sprintf("Gohs-ladon Service %s", Version),
		Run:     run,
		PreRunE: preRunE,
	}
	rootCmd.Flags().Bool("debug", false, "Enable debug mode")
	rootCmd.Flags().Int("port", 8080, "Listen port")
	rootCmd.Flags().String("filepath", "", "Dict file path")
	rootCmd.Flags().String("flag", "iou", "Regex Flag")

	viper.BindPFlag("debug", rootCmd.Flags().Lookup("debug"))
	viper.BindPFlag("port", rootCmd.Flags().Lookup("port"))
	viper.BindPFlag("filepath", rootCmd.Flags().Lookup("filepath"))
	viper.BindPFlag("flag", rootCmd.Flags().Lookup("flag"))

	rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) {
	// Todo add a goroutine to check if pattern file changed, and reload file.

	// start web service
	//http.Handle("/", middleware(http.HandlerFunc(matchHandle)))
	//http.Handle("/_stats", middleware(http.HandlerFunc(statsHandle)))

	addr := fmt.Sprintf("0.0.0.0:%d", Port)
	r := gin.Default()
	r.POST("/scanTar", scanTar)
	if err := r.Run(":"+strconv.Itoa(Port)); err != nil {
		log.Fatal(err)
	}

	/*s := &http.Server{
		Addr:         addr,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}*/
	Uptime = time.Now()

	fmt.Printf("[%s] gohs-ladon %s Running on %s\n", Uptime.Format(time.RFC3339), Version, addr)
	/*if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}*/

}

func preRunE(cmd *cobra.Command, args []string) error {
	Debug = viper.GetBool("debug")
	Port = viper.GetInt("port")
	FilePath = viper.GetString("filepath")
	Flag = viper.GetString("flag")

	if FilePath == "" {
		return fmt.Errorf("empty regex filepath")
	}
	if Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.Debug("Prerun", args)
	RegexMap = make(map[int]RegexLine)
	err := buildScratch(FilePath)
	return err
}

// build scratch for regex file.
func buildScratch(filepath string) (err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	patterns := []*hyperscan.Pattern{}
	var expr hyperscan.Expression
	var id int
	//flags := Flag
	//flags := hyperscan.Caseless | hyperscan.Utf8Mode
	flags, err := hyperscan.ParseCompileFlag(Flag)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		log.Debug(scanner.Text())
		line := scanner.Text()
		// line start with #, skip
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			log.Info(fmt.Sprintf("line start with #, skip line: %s", line))
			continue
		}
		s := strings.SplitN(line, "\t", 3)
		// length less than 3, skip
		if len(s) < 3 {
			log.Info(fmt.Sprintf("line length less than 3, skip line: %s", line))
			continue
		}
		id, err = strconv.Atoi(s[0])
		if err != nil {
			return fmt.Errorf("Atoi error.")
		}
		expr = hyperscan.Expression(s[1])
		data := s[2]
		pattern := &hyperscan.Pattern{Expression: expr, Flags: flags, Id: id}
		patterns = append(patterns, pattern)
		RegexMap[id] = RegexLine{string(expr), data}
	}
	if len(patterns) <= 0 {
		return fmt.Errorf("Empty regex")
	}
	log.Info(fmt.Sprintf("regex file line number: %d", len(patterns)))
	log.Info("Start Building, please wait...")
	db, err := hyperscan.NewBlockDatabase(patterns...)
	Db = db

	if err != nil {
		return err
	}
	scratch, err := hyperscan.NewScratch(Db)
	if err != nil {
		return err
	}
	Scratch.s = scratch

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func initScanner() (*map[string][]MatchResp, func(filepath string, lineno int) func(id uint, from, to uint64, flags uint, context interface{}) error){
	var matchResps = make(map[string][]MatchResp, 100)
	eventHandlerClosure := func (filepath string, lineno int) func(id uint, from, to uint64, flags uint, context interface{}) error {
		return func(id uint, from, to uint64, flags uint, context interface{}) error {
			regexLine, ok := RegexMap[int(id)]
			if !ok || 0 == int(to){
				log.Info(fmt.Sprintf("id: %d, from: %d, to: %d, flags: %v, context: %s", id, from, to, flags, context))
				return nil
			}
			matchResp := MatchResp{Line: lineno, Id: int(id), From: int(from), To: int(to), Flags: int(flags), Context: fmt.Sprintf("%s", context), RegexLinev: regexLine}
			if _, ok := matchResps[filepath]; !ok {
				matchResps[filepath] = make([]MatchResp, 0)
			}
			matchResps[filepath] = append(matchResps[filepath], matchResp)
			return nil
		}
	}
	return &matchResps, eventHandlerClosure
}

func scanLine(query string, filepath string, lineno int, eventHandlerClosure func (filepath string, lineno int) func(id uint, from, to uint64, flags uint, context interface{}) error) error {
	inputData := []byte(query)
	// lock scratch
	Scratch.Lock()
	defer Scratch.Unlock()
	// unlock scratch
	if err := Db.Scan(inputData, Scratch.s, eventHandlerClosure(filepath, lineno), inputData); err != nil {
		logFields := log.Fields{"query": query}
		log.WithFields(logFields).Error(err)
		return err
	}
	return nil
}

func getScanFunc(eventHandlerClosure func (filepath string, lineno int) func(id uint, from, to uint64, flags uint, context interface{}) error) func(path string, f os.FileInfo, err error) error{
	return func(path string, f os.FileInfo, err error) error{
		if f.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var lineno int
		for scanner.Scan() {
			lineno++
			line := scanner.Text()
			// line start with #, skip
			if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.HasPrefix(strings.TrimSpace(line), "//") ||
				strings.HasPrefix(strings.TrimSpace(line), "/*") || strings.HasPrefix(strings.TrimSpace(line), "*") || 0 == len(line) {
				continue
			}
			scanLine(line, path, lineno, eventHandlerClosure)
		}
		return nil
	}
}

func scanTar(c *gin.Context) {
	matchResps, eventHandlerClosure := initScanner()
	uploadDir := "upload_files"
	// single file
	file, err := c.FormFile("file")
	if nil != err {
		c.JSON(http.StatusOK, gin.H{"code":101, "msg": "file empty"})
		return
	}
	if ! strings.HasSuffix(file.Filename, ".tar.gz") {
		c.JSON(http.StatusOK, gin.H{"code":102, "msg": "you should upload tar.gz file"})
		return
	}
	subPath := uploadDir + "/"+file.Filename
	scanPath := c.PostForm("scan_path")
	if 0 == len(scanPath) {
		c.JSON(http.StatusOK, gin.H{"code":103, "msg": "scan_path empty"})
		return
	}
	log.Println(file.Filename)

	if err := os.Mkdir(uploadDir, 0755); nil != err && !os.IsExist(err) {
		c.JSON(http.StatusOK, gin.H{"code":104, "msg": "create dir upload_files failed "+err.Error()})
		return
	}
	if err := os.Mkdir(subPath, 0755); nil != err{
		if os.IsExist(err) {
			if err := os.RemoveAll(subPath); nil != err {
				c.JSON(http.StatusOK, gin.H{"code": 203, "msg": "remove dir "+subPath+" failed "+err.Error()})
				return
			}
			if err := os.Mkdir(subPath, 0755); nil != err{
				c.JSON(http.StatusOK, gin.H{"code": 201, "msg": "create dir "+subPath+" failed "+err.Error()})
				return
			}
		}else {
			c.JSON(http.StatusOK, gin.H{"code": 202, "msg": "create dir "+subPath+" failed "+err.Error()})
			return
		}
	}
	if err := DeCompress(file, subPath+"/"); nil != err{
		c.JSON(http.StatusOK, gin.H{"code":106, "msg": "decompress failed "+err.Error()})
		return
	}
	if _, err := os.Stat(subPath+"/"+scanPath); err != nil {
		c.JSON(http.StatusOK, gin.H{"code":107, "msg": err.Error()})
		return
	}

	scanFunc := getScanFunc(eventHandlerClosure)

	Scandir(subPath+"/"+scanPath, scanFunc)

	outputStr := formatOutputHtml(subPath, *matchResps)

	c.String(200, outputStr)

}

func formatOutputHtml(prefix string, matchResps map[string][]MatchResp) string{
	var strArr []string
	var fileArr []string
	strArr = append(strArr, "<body><table>")
	strArr = append(strArr, "<tr><th>file</th><th>matchRuleName</th><th>line</th><th>desc</th></tr>")
	for file, _ := range matchResps{
		fileArr = append(fileArr, file)
	}
	sort.Strings(fileArr)
	for _, file := range fileArr {
		matchLines := matchResps[file]
		for _, matchLine := range matchLines {
			strArr = append(strArr, "<tr><td>" + strings.TrimPrefix(file, prefix) + ":" + strconv.Itoa(matchLine.Line) + ":" + strconv.Itoa(matchLine.From) + ":" + strconv.Itoa(matchLine.To) + "</td>")
			strArr = append(strArr, "<td>" + matchLine.RegexLinev.Expr + "</td><td>" + matchLine.Context + "</td><td>" + matchLine.RegexLinev.Data + "</td></tr>")
		}
	}
	strArr = append(strArr, "</table></body>")
	return strings.Join(strArr, "")
}

func Scandir(dir string, visit func (path string, f os.FileInfo, err error) error){
	err := filepath.Walk(dir, visit)
	fmt.Printf("filepath.Walk() returned %v\n", err)
}

func DeCompress(fileUploaded *multipart.FileHeader, dest string) error {
	srcFile, err := fileUploaded.Open()
	if err != nil {
		return err
	}
	defer srcFile.Close()
	gr, err := gzip.NewReader(srcFile)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	var file *os.File
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}
		filename := dest + hdr.Name
		if strings.HasSuffix(filename, "/") {
			err = os.Mkdir(filename, 0755)
		}else{
			file, err = createFile(filename)
		}
		if err != nil {
			return err
		}
		if !strings.HasSuffix(filename, "/") {
			io.Copy(file, tr)
		}
	}
	return nil
}

func createFile(name string) (*os.File, error) {
	err := os.MkdirAll(string([]rune(name)[0:strings.LastIndex(name, "/")]), 0755)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	return os.Create(name)
}
