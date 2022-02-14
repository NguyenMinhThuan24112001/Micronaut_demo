package com.example.repository;

import com.example.models.DiemThi;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;
import io.micronaut.data.repository.CrudRepository;

import java.util.List;
import java.util.Optional;

@Repository
public interface QLDiemThiRepository extends JpaRepository<DiemThi,Long> {
    @Query("select coalesce(max(d.lanThi), 0) from DiemThi d where d.monHoc.id=:maMh and d.sinhVien.id=:maSv")
    Optional<Long> findLanThiMaxByMaSVandMaMH(@Parameter("maSv") Long maSV,
                                                 @Parameter("maMh") Long maMH);
    @Query("select d.sinhVien.ten from DiemThi d where d.monHoc.id=:maMh and d.sinhVien.id=:maSv")
    Optional<Long> findNameByMaSVandMaMH(@Parameter("maSv") Long maSV,
                                              @Parameter("maMh") Long maMH);

    @Query("select coalesce(max(d.diem), 0) from DiemThi d where d.monHoc.id=:maMh and d.sinhVien.id=:maSv " +
            "and (select max(d1.lanThi) from DiemThi d1 where d1.monHoc.id=:maMh and d1.sinhVien.id=:maSv)=d.lanThi")
    Optional<Double> findDiemThiByMaSVandMaMH(@Parameter("maSv") Long maSV,
                                              @Parameter("maMh") Long maMH);

    Optional<DiemThi> findFirstByMonHocIdAndSinhVienIdOrderByIdDesc(Long maMH, Long maSV);


    @Query("from DiemThi d where d.id in (select max(d1.id) from DiemThi d1 where d1.sinhVien.id=:maSv group by d1.monHoc.id)")
    List<DiemThi> findAllBySinhVienIsTrue(@Parameter("maSv") Long maSv);
}
