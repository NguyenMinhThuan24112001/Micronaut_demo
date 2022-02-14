package com.example.service;

import com.example.models.MonHoc;
import com.example.repository.QLMonHocRepository;
import io.micronaut.http.HttpResponse;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.hibernate.annotations.NotFound;

import java.util.List;

@Singleton
public class MonHocService {
    @Inject
    QLMonHocRepository qlMonHoc;

    // lay tat cac notes
    public List<MonHoc> getAllMonHoc() {
        return qlMonHoc.findAll();
    }

    // Tao mot note moi
    public MonHoc createMonHoc(MonHoc monHoc) {
        return qlMonHoc.save(monHoc);
    }

    // lay ra mot note bat ki
    public MonHoc getMonHocById(Long monHocId) {
        return qlMonHoc.findById(monHocId)
                .orElseThrow(null);
    }
    public Long geMonHocById(Long monHocId) {
        return qlMonHoc.findById(monHocId).get().getId();
        //.orElseThrow(() -> new ResourceNotFoundException("MonHoc", "id", monHocId));
    }

    // cap nhat thay doi mot note
    public MonHoc updateMonHoc(Long monHocId, MonHoc monHocDetails) {

        MonHoc monHoc = qlMonHoc.findById(monHocId)
                .orElseThrow(null);

        monHoc.setTenMH(monHocDetails.getTenMH());
        MonHoc updatedMonHoc = qlMonHoc.save(monHoc);
        return updatedMonHoc;
    }

    // xoa mot node
    public HttpResponse<?> deleteMonHoc(Long monHocId) {
        MonHoc monHoc = qlMonHoc.findById(monHocId)
                .orElseThrow(null);

        qlMonHoc.deleteById(monHocId);
        return HttpResponse.noContent();
    }
}
