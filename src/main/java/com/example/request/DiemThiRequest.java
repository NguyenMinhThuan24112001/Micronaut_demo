package com.example.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Introspected;
import lombok.Data;

@Data
@Introspected
public class DiemThiRequest {

    @JsonProperty("maSv")
    private Long mSSV;

    @JsonProperty("maMh")
    private Long mSMH;

    @JsonProperty("diemThi")
    private Double diemThi;

}
