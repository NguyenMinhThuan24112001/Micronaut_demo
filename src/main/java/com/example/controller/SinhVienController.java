package com.example.controller;

import com.example.models.DiemThi;
import com.example.models.MonHoc;
import com.example.models.SinhVien;
import com.example.request.DiemThiRequest;
import com.example.response.DiemThiCuoiReponse;
import com.example.response.NoteSinhVienReponse;
import com.example.response.SinhVienReponse;
import com.example.service.DiemThiService;
import com.example.service.MonHocService;
import com.example.service.SinhVienService;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.*;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import jakarta.inject.Inject;
import lombok.Data;

import javax.validation.Valid;
import java.util.List;

@Secured(SecurityRule.IS_ANONYMOUS)
@Controller("/api")
public class SinhVienController {

    //Sinh Vien
    @Inject
    SinhVienService sinhVienService;

    public List<SinhVien> getAllSinhVien() {
        return sinhVienService.getAllSinhVien();
    }

    // Tao mot note moi
    @Post("/sinhvien")
    public SinhVien createSinhVien(@Valid @Body SinhVien sinhVien) {

        return sinhVienService.createSinhVien(sinhVien);
    }

    // lay ra mot note bat ki
    @Get("/sinhvien/{id}")
    public SinhVien getSinhVienById(@PathVariable(value = "id") Long sinhVienId) {
        return sinhVienService.getSinhVienById(sinhVienId);
    }

    // cap nhat thay doi mot note
    @Put("/sinhvien/{id}")
    public SinhVien updateSinhVien(@PathVariable(value = "id") Long sinhVienId,
                                   @Valid @Body SinhVien sinhVienDetails) {
        return sinhVienService.updateSinhVien(sinhVienId, sinhVienDetails);
    }

    // xoa mot node
    @Delete("/sinhvien/{id}")
    public HttpResponse<?> deleteSinhVien(@PathVariable(value = "id") Long sinhVienId) {
        return sinhVienService.deleteSinhVien(sinhVienId);
    }


    //Mon  Hoc
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

    @Get("/monhocs/{id}")
    public Long getMonHocsById(@PathVariable(value = "id") Long monHocId) {
        return monHocService.geMonHocById(monHocId);
    }


    //diem thi

    @Inject
    DiemThiService diemThiService;

    // Tao mot note moi
    @Post("/diemthi")
    public DiemThi createDiemThi(@Valid @Body DiemThiRequest diemThi) {

        return diemThiService.createDiemThi(diemThi);
    }

    // lay ra mot note bat ki
    @Get("/diemthi/{id}")
    public DiemThi getDiemThiById(@PathVariable(value = "id") Long diemThiId) {
        return diemThiService.getDiemThiById(diemThiId);
    }

    // cap nhat thay doi mot note
    @Put("/diemthi")
    public DiemThi updateDiemThi(@Valid @Body UpdateDiemThiDto dto) {
        return diemThiService.updateDiemThi(dto);
    }

    @Data
    @Introspected
    public static class UpdateDiemThiDto {
        private Long diemThiId;
        private Double diemMoi;
    }

    // xoa mot node
    @Delete("/diemthi/{id}")
    public HttpResponse<?> deleteDiemThi(@PathVariable(value = "id") Long diemThiId) {
        return diemThiService.deleteDiemThi(diemThiId);
    }

    @Get("/lanthimax")
    public SinhVienReponse getLanThiMax(@Nullable @QueryValue("maSV") Long maSV,
                                        @QueryValue("maMH") Long maMH) {
        return diemThiService.findLanThiMax(maSV, maMH);
    }

    @Get("/diemthilancuoi")
    public DiemThiCuoiReponse getDiemThiLanCuoi(@Nullable @QueryValue("maSV") Long maSV,
                                                @Nullable @QueryValue("maMH") Long maMH) {
        return diemThiService.findDiemThi(maSV, maMH);
    }

    //    @Get("/diemthilancuoipart2")
//    public DiemThi getDiemThiLanCuoiPart2(@Nullable @QueryValue("maMH") Long maMH,
//                                          @Nullable @QueryValue("maSV") Long maSV) {
//        return diemThiService.findDiemThiCuoi(maMH,maSV);
//    }

    //diem thi lan cuoi cua cac mon hoc cua moi sinh vien
    @Get("/sinhvienhoc")
    public List<NoteSinhVienReponse> getSinhVienHoc(@Nullable @QueryValue("maSV") Long maSv) {
        return diemThiService.findSinhVien(maSv);
    }
}
