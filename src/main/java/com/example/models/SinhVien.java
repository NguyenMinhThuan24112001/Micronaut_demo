package com.example.models;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.data.annotation.DateCreated;
import io.micronaut.data.annotation.DateUpdated;
import io.micronaut.http.annotation.Get;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;


@Entity
@Getter
@Setter
@AllArgsConstructor
@Table(name = "sinhVien")
@Introspected
public class SinhVien {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)// giá trị sẽ tự sinh ra
    private Long id;

    @NotBlank
    private String ho;

    @NotBlank
    private String ten;

    @NotBlank
    private String lop;

    private boolean gioiTinh;

    private LocalDate ngaySinh;

    public SinhVien() {

    }
}
