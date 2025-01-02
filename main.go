package main

import (
	"context"
	"fmt"
	"log"

	vts "github.com/Viktor-8bit/virustotal-api-go/vrscaner"
)

func main() {

	ctx := context.Background()

	vtscaner := vts.NewVTScaner("your_api_token")

	// получаем ID url после сканирования
	urlID, err := vtscaner.ScanURL(ctx, "amazonstorepro.com")

	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println("ID url: ", urlID)

	// либо каждый раз ждать перед получением отчета time.Sleep(5 * time.Second)

	// получаем последний report по ID url
	result, err := vtscaner.GetReport(ctx, urlID)

	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println("Дата сканирования: ", result.ScanDate)

	for _, result := range result.Results {
		fmt.Printf("%+v\n", result)
	}

	// либо добавить повторный запрос с ожиданием секунд 30 в случае если result.length == 0

	// конвертируем в json
	json, err := vts.ToJson(result)

	if err != nil {
		log.Println(err)
	}

	fmt.Println(string(json))
}
