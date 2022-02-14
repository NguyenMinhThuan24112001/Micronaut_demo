package com.example.models;


import io.micronaut.core.annotation.Introspected;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;

@Entity
@Setter
@Getter
@AllArgsConstructor
@Table(name = "monHoc")
@Introspected
public class MonHoc {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)// giá trị sẽ tự sinh ra
    private Long id;

    @NotBlank
    private String tenMH;


    public MonHoc() {

    }
}
