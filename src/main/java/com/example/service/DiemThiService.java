package com.example.service;

import com.example.controller.SinhVienController;
import com.example.models.DiemThi;
import com.example.models.MonHoc;
import com.example.models.SinhVien;
import com.example.repository.QLDiemThiRepository;
import com.example.repository.QLMonHocRepository;
import com.example.repository.QLSinhVienRepository;
import com.example.request.DiemThiRequest;
import com.example.response.DiemThiCuoiReponse;
import com.example.response.NoteSinhVienReponse;
import com.example.response.SinhVienReponse;
import io.micronaut.core.type.Argument;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.http.HttpResponse;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Singleton
public class DiemThiService {
    @Inject
    QLDiemThiRepository qlDiemThiRepository;

    @Inject
    QLMonHocRepository qlMonHoc;


    @Inject
    QLSinhVienRepository qlSinhVienRepository;


    // lay tat cac notes
    //  public List<DiemThi> getAllDiemThi() {
//        return qlDiemThiRepository.findAll();
//    }

    // Tao mot note moi
    public DiemThi createDiemThi(DiemThiRequest diemThiRequest) {
        DiemThi diemThi = new DiemThi();
        //  diemThi.setCreatedAt(LocalDateTime.now());
        SinhVien sv = qlSinhVienRepository.findById(diemThiRequest.getMSSV()).orElse(null);
        MonHoc mh = qlMonHoc.findById(diemThiRequest.getMSMH()).orElse(null);
        diemThi.setMonHoc(mh);
        diemThi.setSinhVien(sv);
        diemThi.setDiem(diemThiRequest.getDiemThi());
        return qlDiemThiRepository.save(diemThi);
    }

    // lay ra mot note bat ki
    public DiemThi getDiemThiById(Long diemThiId) {
        return qlDiemThiRepository.findById(diemThiId)
                .orElseThrow(null);
    }

    // cap nhat thay doi mot note
    public DiemThi updateDiemThi(SinhVienController.UpdateDiemThiDto dto) {
        return qlDiemThiRepository.findById(dto.getDiemThiId()).map(diemThi -> {
            diemThi.setDiem(dto.getDiemMoi());
            return qlDiemThiRepository.save(diemThi);
        }).orElse(null);
    }

    // xoa mot node
    public HttpResponse<?> deleteDiemThi(Long diemThiId) {
        DiemThi diemThi = qlDiemThiRepository.findById(diemThiId)
                .orElseThrow(null);

        qlDiemThiRepository.deleteById(diemThiId);
        return HttpResponse.noContent();
    }

    public SinhVienReponse findLanThiMax(Long maSv, Long maMh) {
        SinhVienReponse sinhVienResonse = new SinhVienReponse();
        sinhVienResonse.setMaSv(maSv);
        sinhVienResonse.setMaMh(maMh);
        sinhVienResonse.setLanThiMax(qlDiemThiRepository.findLanThiMaxByMaSVandMaMH(maSv, maMh).orElse(null));
        return sinhVienResonse;
    }

    public DiemThiCuoiReponse findDiemThi(Long maSv, Long maMh) {
        DiemThiCuoiReponse diemThiCuoiReponse = new DiemThiCuoiReponse();
        diemThiCuoiReponse.setMaSv(maSv);
        diemThiCuoiReponse.setMaMh(maMh);
        diemThiCuoiReponse.setLanThi(qlDiemThiRepository.findLanThiMaxByMaSVandMaMH(maSv, maMh).orElse(null));
        diemThiCuoiReponse.setDiemThi(qlDiemThiRepository.findDiemThiByMaSVandMaMH(maSv, maMh).orElse(null));
        return diemThiCuoiReponse;
    }

    public DiemThi findDiemThiCuoi(Long maMh, Long maSv) {
        DiemThi diemThi1 = qlDiemThiRepository.findFirstByMonHocIdAndSinhVienIdOrderByIdDesc(maMh, maSv).orElse(null);
        return diemThi1;
    }

    public List<NoteSinhVienReponse> findSinhVien(Long maSv) {

        return qlDiemThiRepository.findAllBySinhVienIsTrue(maSv).stream().map(diemThi -> {
            NoteSinhVienReponse noteSinhVienReponse = new NoteSinhVienReponse();
            noteSinhVienReponse.setName(diemThi.getSinhVien().getTen());
            noteSinhVienReponse.setMaMh(diemThi.getMonHoc().getId());
            noteSinhVienReponse.setMaSv(maSv);
            noteSinhVienReponse.setLanThi(diemThi.getLanThi());
            noteSinhVienReponse.setDiemThi(diemThi.getDiem());
            return noteSinhVienReponse;
        }).collect(Collectors.toList());
    }
}
