package com.example.repository;

import com.example.models.MonHoc;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jpa.repository.JpaRepository;
import io.micronaut.data.repository.CrudRepository;

@Repository
public interface QLMonHocRepository extends JpaRepository<MonHoc,Long> {
}
