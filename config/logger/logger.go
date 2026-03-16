package logger

// 日志组件
import (
	"io"
	"os"
	"strings"
	"time"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type tprint func(args ...interface{})
type tprintf func(string, ...interface{})

type Level zapcore.Level

const (
	// DebugLevel logs are typically voluminous, and are usually disabled in
	// production.
	DebugLevel Level = iota - 1
	// InfoLevel is the default logging priority.
	InfoLevel
	// WarnLevel logs are more important than Info, but don't need individual
	// human review.
	WarnLevel
	// ErrorLevel logs are high-priority. If an application is running smoothly,
	// it shouldn't generate any error-level logs.
	ErrorLevel
	// DPanicLevel logs are particularly important errors. In development the
	// logger panics after writing the message.
	DPanicLevel
	// PanicLevel logs a message, then panics.
	PanicLevel
	// FatalLevel logs a message, then calls os.Exit(1).
	FatalLevel
)

var (
	// 只能输出结构化日志，但是性能要高于 SugaredLogger
	zLogger *zap.Logger
	// 可以输出 结构化日志、非结构化日志。性能比zap.Logger低
	zSugLogger *zap.SugaredLogger
	// 日志等级
	// deflvl zapcore.Level
	deflvl zap.AtomicLevel
	// 定义多个日志函数
	Debug   tprint
	Debugf  tprintf
	Info    tprint
	Infof   tprintf
	Warn    tprint
	Warnf   tprintf
	Error   tprint
	Errorf  tprintf
	DPanic  tprint
	DPanicf tprintf
	Panic   tprint
	Panicf  tprintf
	Fatal   tprint
	Fatalf  tprintf

	// 只能输出结构化日志，但是性能要高于 SugaredLogger
	zFuncLogger *zap.Logger
	// 可以输出 结构化日志、非结构化日志。性能比zap.Logger低
	zFuncSugLogger *zap.SugaredLogger
	// 定义多个日志函数，不能直接使用，需要用函数包装使用
	FuncDebugf tprintf
	FuncInfof  tprintf
	FuncErrorf tprintf
)
var SaramaErrorHook func(msg string)

// 日志参数
type Args struct {
	BasePath string // 日志文件基本路径，不传入会自动根据ProjectName生成Tars路径
	// Level       string // 日志等级，DEBUG, INFO, WARN, ERROR, FATAL
	ProjectName string // 项目名称
	ServerName  string // 服务名称
	MaxSize     int    // 单日志大小限制，超过则切割，单位：MB
	MaxBackups  int    // 总日志文件数量，超过就删除最老的日志文件
	MaxAge      int    // 日志文件最大保留天数
	Compress    bool   // 日志文件是否压缩
	logPath     string // 日志真实路径
	Console     bool   // 是否仅输出到控制台
}

// 检查并触发
func checkAndHandleError(msg string) {
	if strings.Contains(msg, "Request was for a topic or partition that does not exist") {
		if SaramaErrorHook != nil {
			SaramaErrorHook(msg)
		}
	}
}

func Init(args *Args) {
	// 参数校验
	if args == nil {
		args = &Args{}
	}
	if args.ServerName == "" {
		panic("日志组件初始化异常，服务名称不能为空")
	}
	if args.ProjectName == "" {
		args.ProjectName = ""
	}
	if args.BasePath == "" {
		args.BasePath = "/"
	}
	if args.MaxSize <= 0 {
		args.MaxSize = 50
	}
	if args.MaxBackups <= 0 {
		args.MaxBackups = 10
	}
	if args.MaxAge <= 0 {
		args.MaxAge = 30
	}
	// fmt.Printf("初始化日志参数：%v\n", *args)

	// 创建日志资源
	if zLogger != nil {
		zLogger.Sync()
	}
	if zSugLogger != nil {
		zSugLogger.Sync()
	}
	args.logPath = args.BasePath
	_, err := os.Stat(args.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(args.logPath, 0755); err != nil {
				panic(err)
			}
		}
	}

	// 初始化日志配置
	initLogFile(args)

	// 初始化日志函数
	initFunc(args)

	// 初始化 zap logger
	initLogFile(args)
	initFunc(args)

	// 打印第一条日志
	// Infof("%s-%s server initial success, log path is %s", args.ProjectName, args.ServerName, args.logPath)
}

func initFunc(args *Args) {
	Debug = zSugLogger.Debug
	Debugf = zSugLogger.Debugf
	Info = zSugLogger.Info
	Infof = zSugLogger.Infof
	Warn = zSugLogger.Warn
	Warnf = zSugLogger.Warnf
	Error = zSugLogger.Error
	Errorf = zSugLogger.Errorf
	DPanic = zSugLogger.DPanic
	DPanicf = zSugLogger.DPanicf
	Panic = zSugLogger.Panic
	Panicf = zSugLogger.Panicf
	Fatal = zSugLogger.Fatal
	Fatalf = zSugLogger.Fatalf
	FuncDebugf = zFuncSugLogger.Debugf
	FuncInfof = zFuncSugLogger.Infof
	FuncErrorf = zFuncSugLogger.Errorf
}

func ChangeLevel(lev Level) {
	// deflvl = lev
	deflvl.SetLevel(zapcore.Level(lev))
}

func initLogFile(args *Args) {
	// 创建日志编码器
	encoder := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		MessageKey:   "msg",                       // 结构化输出：msg的key
		LevelKey:     "loglevel",                  // 结构化输出：日志级别的key（INFO，WARN，ERROR等）
		TimeKey:      "time",                      // 结构化输出：时间的key（INFO，WARN，ERROR等）
		CallerKey:    "all",                       // 结构化输出：打印日志的文件对应的Key
		EncodeLevel:  zapcore.CapitalLevelEncoder, // 将日志级别转换成大写（INFO，WARN，ERROR等）
		EncodeCaller: zapcore.ShortCallerEncoder,  // 采用短文件路径编码输出（test/main.go:14 ）
		EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) { // 日志文件时间格式
			enc.AppendString(t.Format("2006-01-02 15:04:05.000"))
		},
		EncodeDuration: func(d time.Duration, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendInt64(int64(d) / 1000000)
		},
		ConsoleSeparator: " | ", // 日志分隔符
	})
	// 实现判断日志等级的interface
	// logLevel := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
	// 	return lvl >= deflvl
	// })
	deflvl = zap.NewAtomicLevel()
	deflvl.SetLevel(zapcore.InfoLevel)
	// 创建回滚日志记录器
	// loopWriter := createLoopWriter(args)

	// 最后创建具体的Logger
	// core := zapcore.NewTee(
	// 	zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), logLevel),  // 屏幕打印
	// 	zapcore.NewCore(encoder, zapcore.AddSync(loopWriter), logLevel), // 普通信息打印
	// )

	// only paint to screen ?
	var ws zapcore.WriteSyncer
	if args.Console {
		ws = zapcore.NewMultiWriteSyncer(
			zapcore.AddSync(os.Stdout),              // 屏幕打印
			zapcore.AddSync(createLoopWriter(args)), // 普通信息打印
		)
	} else {
		ws = zapcore.NewMultiWriteSyncer(
			zapcore.AddSync(createLoopWriter(args)), // 普通信息打印
		)
	}

	core := zapcore.NewCore(
		encoder,
		ws,
		deflvl,
	)

	// 构造日志
	// zLogger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(0)) // 需要传入 zap.AddCaller() 才会显示打日志点的文件名和行数, 有点小坑
	zLogger = zap.New(core, zap.AddCaller()) // 需要传入 zap.AddCaller() 才会显示打日志点的文件名和行数, 有点小坑
	zSugLogger = zLogger.Sugar()
	zFuncLogger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1)) // 需要传入 zap.AddCaller() 才会显示打日志点的文件名和行数, 有点小坑
	zFuncSugLogger = zFuncLogger.Sugar()
}

func createLoopWriter(args *Args) io.Writer {
	return &lumberjack.Logger{
		Filename:   args.logPath + "/" + args.ServerName + ".log",
		MaxSize:    args.MaxSize,    // 单日志大小限制，超过则切割，单位：MB
		MaxBackups: args.MaxBackups, // 总日志文件数量，超过就删除最老的日志文件
		MaxAge:     args.MaxAge,     // 日志文件最大保留天数
		Compress:   args.Compress,   // 日志文件是否压缩
		LocalTime:  true,            // 是否启用本地时间，默认为UTC标准时间
	}
}

// 用于延时打印返回值
func DeferError(reqID string, reterr *error) {
	err := *reterr
	if err != nil {
		FuncErrorf("Found error reqID:%s err:%v", reqID, err)
	} else {
		// FuncDebugf("All done reqID:%s", reqID)
	}
}

// 用于延时打印返回值
func DeferPrintRet(reqID string, reterr *error) {
	err := *reterr
	if err != nil {
		FuncErrorf("Found error reqID:%s err:%v", reqID, err)
	} else {
		FuncDebugf("All done reqID:%s", reqID)
	}
}
