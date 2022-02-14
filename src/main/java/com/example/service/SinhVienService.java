package com.example.service;

import com.example.models.SinhVien;
import com.example.repository.QLSinhVienRepository;
import io.micronaut.http.HttpResponse;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.util.List;

@Singleton
public class SinhVienService {
    @Inject
    QLSinhVienRepository qlSinhVienRepository;

    // lay tat cac notes
    public List<SinhVien> getAllSinhVien() {
        return qlSinhVienRepository.findAll();
    }

    // Tao mot note moi
    public SinhVien createSinhVien(SinhVien sinhVien) {
        return qlSinhVienRepository.save(sinhVien);
    }

    // lay ra mot note bat ki
    public SinhVien getSinhVienById(Long sinhVienId) {
        return qlSinhVienRepository.findById(sinhVienId)
                .orElseThrow(null);
    }

    // cap nhat thay doi mot note
    public SinhVien updateSinhVien(Long sinhVienId, SinhVien sinhVienDetails) {

        SinhVien sinhVien = qlSinhVienRepository.findById(sinhVienId)
                .orElseThrow(null);

        sinhVien.setTen(sinhVienDetails.getTen());
        sinhVien.setHo(sinhVienDetails.getHo());
        sinhVien.setLop(sinhVienDetails.getLop());

        SinhVien updatedSinhVien = qlSinhVienRepository.save(sinhVien);
        return updatedSinhVien;
    }

    // xoa mot node
    public HttpResponse<?> deleteSinhVien(Long sinhVienId) {
        SinhVien sinhVien = qlSinhVienRepository.findById(sinhVienId)
                .orElseThrow(null);

        qlSinhVienRepository.deleteById(sinhVienId);
        return HttpResponse.noContent();
    }

}
