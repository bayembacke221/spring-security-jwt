package sn.bayembacke.jwt.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import sn.bayembacke.jwt.model.AuthenticateRequest;
import sn.bayembacke.jwt.model.AuthenticateResponse;
import sn.bayembacke.jwt.service.MyUserDetailsService;
import sn.bayembacke.jwt.util.JwtUtil;

@RestController
public class HomeController {
    private AuthenticationManager authenticationManager;

    MyUserDetailsService userDetailsService;

    private JwtUtil jwtUtil;

    public HomeController(AuthenticationManager authenticationManager,
                          MyUserDetailsService userDetailsService, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping({"/hello"})
    public String hello(){
        return "<h1>Hello</h1>";
    }


    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(
            @RequestBody AuthenticateRequest request
    ) throws Exception {
        try{
           authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        } catch (BadCredentialsException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
;
        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(request.getUsername());

        final  String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticateResponse(jwt));
    }
}
