package com.example.demo.models;

import com.vladmihalcea.hibernate.type.json.JsonType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Type;

import java.util.List;

@Entity
@Table(name = "candidates")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Candidate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String firstName;
    private String lastName;
    private String headline;
    private String summary;


    // Store list of skills as JSON in a single column
    @Type(JsonType.class)
    @Column(columnDefinition = "jsonb")
    private List<String> skills;
    @OneToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;


}
