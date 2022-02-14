package com.example.response;

import io.micronaut.core.annotation.Introspected;
import lombok.Data;

@Data
@Introspected
public class DiemThiCuoiReponse {
    private Long maSv;

    private Long maMh;

    private Long lanThi;

    private Double diemThi;
}
