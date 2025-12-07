package com.example.demo.services.impl;

import com.example.demo.exception.ConflictException;
import com.example.demo.exception.UnauthorizedActionException;
import com.example.demo.models.Candidate;
import com.example.demo.models.Employer;
import com.example.demo.models.Role;
import com.example.demo.models.User;
import com.example.demo.models.enumeration.ERole;
import com.example.demo.payload.request.LoginRequest;
import com.example.demo.payload.request.SignupRequest;
import com.example.demo.exception.response.JwtResponse;
import com.example.demo.repository.CandidateRepository;
import com.example.demo.repository.EmployerRepository;
import com.example.demo.repository.RoleRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.jwt.JwtUtils;
import com.example.demo.security.services.UserDetailsImpl;
import com.example.demo.services.AuthServices;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class AuthServicesImpl implements AuthServices {
    private final CandidateRepository candidateRepository;
    private final EmployerRepository employerRepository;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;


    @Override
    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            //return new JwtResponse(jwt,"Bearer", userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles);
            return JwtResponse.builder()
                    .token(jwt)
                    .type("Bearer")
                    .id(userDetails.getId())
                    .username(userDetails.getUsername())
                    .email(userDetails.getEmail())
                    .roles(roles)
                    .build();
         } catch (BadCredentialsException e) {
            throw new UnauthorizedActionException("Invalid username or password");
         }
    }

    @Override
    public void registerUser(SignupRequest signUpRequest) {
       if (userRepository.existsByUsername(signUpRequest.getUsername())) {
           throw new ConflictException("Username is already taken");
       }
       if (userRepository.existsByEmail(signUpRequest.getEmail().trim())) {
            throw new ConflictException("Email is already in use");
       }

        User user=User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(encoder.encode(signUpRequest.getPassword()))
                .build();

        String roleInput=signUpRequest.getRole();
        Role role = switch (roleInput.toLowerCase()) {
            case "employer" -> roleRepository.findByName(ERole.ROLE_MODERATOR)
                    .orElseThrow(() -> new RuntimeException("Error: Role not found"));
            case "admin" -> roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role not found"));
            default -> roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role not found"));
        };
        user.setRoles(Set.of(role));
        userRepository.save(user);

        if(role.getName()==ERole.ROLE_USER){
            Candidate candidate = Candidate.builder()
                    .user(user)
                    .build();
            candidateRepository.save(candidate);
        } else if (role.getName() == ERole.ROLE_MODERATOR) {
            Employer employer = Employer.builder()
                    .user(user)
                    .build();
            employerRepository.save(employer);
        }
    }
}
