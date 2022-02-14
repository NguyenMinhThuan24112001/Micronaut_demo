package com.example.repository;

import com.example.models.SinhVien;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;
import io.micronaut.data.repository.CrudRepository;

@Repository
public interface QLSinhVienRepository extends JpaRepository<SinhVien,Long> {

}
