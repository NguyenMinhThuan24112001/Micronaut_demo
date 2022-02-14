package com.example.response;


import io.micronaut.core.annotation.Introspected;
import lombok.Data;

@Data
@Introspected
public class SinhVienReponse {
    private Long maSv;

    private Long maMh;

    private Long LanThiMax;
}
