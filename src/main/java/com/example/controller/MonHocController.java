package com.example.controller;

import com.example.models.MonHoc;
import com.example.service.MonHocService;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.*;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import jakarta.inject.Inject;

import javax.validation.Valid;

@Controller("/apis")
public class MonHocController {
    @Inject
    MonHocService monHocService;

    // Tao mot note moi
    @Post("/monhoc")
    public MonHoc createMonHoc(@Valid @Body MonHoc monHoc) {

        return monHocService.createMonHoc(monHoc);
    }

    // lay ra mot note bat ki
    @Get("/monhoc/{id}")
    public MonHoc getMonHocById(@PathVariable(value = "id") Long monHocId) {
        return monHocService.getMonHocById(monHocId);
    }

    // cap nhat thay doi mot note
    @Put("/monhoc/{id}")
    public MonHoc updateMonHoc(@PathVariable(value = "id") Long monHocId,
                               @Valid @Body MonHoc monHocDetails) {
        return monHocService.updateMonHoc(monHocId, monHocDetails);
    }

    // xoa mot node
    @Delete("/monhoc/{id}")
    public HttpResponse<?> deleteMonHoc(@PathVariable(value = "id") Long monHocId) {
        return monHocService.deleteMonHoc(monHocId);
    }

}
