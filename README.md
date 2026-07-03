use Ctrl+F9 and save to reload

Every time we have a new controller endpoint
we need it to include  in the WebSecurityConfig

    @GetMapping("/all")
    public String allAccess() {
        return "Public sContentsss.";
    }
   .requestMatchers("/api/test/all").permitAll() -> all user can access without token public

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }
   .requestMatchers("/api/test/user").hasAnyRole("USER", "MODERATOR", "ADMIN") // user,mod,admin only can access this using token


🧩 Why I Used Spring Data JPA Projections (Interface-Based DTOs)

1️⃣ Why: To make queries faster and lighter ⚡
→ Only fetch the columns I actually need instead of full entities.

2️⃣ Why: To simplify mapping 🧠
→ Spring automatically maps SQL results into an interface — no need to write DTO classes.

3️⃣ Why: To keep it read-only and safe 🔒
→ Projections don’t allow updates or saves, which protects data consistency for query results.

4️⃣ Why: To handle multi-table joins 🧩
→ Perfect for custom queries joining several tables like users, candidates, and roles.

5️⃣ Why: To keep code clean and efficient 🧾
→ Reduces boilerplate and improves readability for data retrieval.

//create an interface for querying join tables
 
    public interface CandidateResponseSearchParam {
    Long getUserId();
    String getFirstName();
    String getLastName();
    String getHeadline();
    String getSummary();
    String getSkills();
    }

    @Query(value = """
        SELECT 
            u.id AS userId,
            c.first_name AS firstName,
            c.last_name AS lastName,
            c.headline AS headline,
            c.summary AS summary,
            CAST(c.skills AS TEXT) AS skills
        FROM users u
        JOIN candidates c ON u.id = c.user_id
        WHERE 
            (:skill IS NULL OR CAST(c.skills AS TEXT) LIKE CONCAT('%', :skill, '%'))
            AND (:headline IS NULL OR c.headline LIKE CONCAT('%', :headline, '%'))
        """, nativeQuery = true)
    List<CandidateResponseSearchParam> searchCandidatesByParam(
        @Param("skill") String skill,
        @Param("headline") String headline
    );
}
