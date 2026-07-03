package com.example.demo.models;


import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "employers")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Employer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String companyName;
    private String industry;
    private String website;
    private String email;
    @OneToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;


}
