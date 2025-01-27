package kan9hee.nolaejui_auth.component

import io.jsonwebtoken.*
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import kan9hee.nolaejui_auth.dto.JwtTokenDTO
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.stereotype.Component
import java.util.*
import java.util.stream.Collectors
import javax.crypto.SecretKey

@Component
class JwtTokenComponent(@Value("\${jwt.secret}") secretKey:String) {

    private val key: SecretKey

    init {
        val keyBytes = Decoders.BASE64.decode(secretKey)
        key = Keys.hmacShaKeyFor(keyBytes)
    }

    fun generateToken(authentication: Authentication): JwtTokenDTO {
        val authorities = authentication
            .authorities
            .stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","))

        val now = Date()

        val accessToken = Jwts.builder()
            .subject(authentication.name)
            .issuedAt(now)
            .claim("auth",authorities)
            .expiration(Date(now.time+600_000))
            .signWith(this.key)
            .compact()

        val refreshToken = Jwts.builder()
            .expiration(Date(now.time + 604_800_000))
            .signWith(this.key)
            .compact()

        return JwtTokenDTO("Bearer ",accessToken,refreshToken)
    }

    fun validateToken(token:String): Boolean {
        return try {
            val claims=getClaimsFromToken(token)

            val expirationDate = claims.expiration
            if (expirationDate.before(Date()))
                return false

            true
        } catch (e: Exception) {
            false
        }
    }

    fun getUsernameFrom(accessToken:String): String? {
        val claims=getClaimsFromToken(accessToken)

        return claims.subject
    }

    private fun getClaimsFromToken(token:String): Claims {
        val claims = try {
            Jwts.parser()
                .verifyWith(this.key)
                .build()
                .parseSignedClaims(token)
                .payload
        } catch (e: Exception) {
            throw RuntimeException("Invalid JWT token: ${e.message}", e)
        }

        if (claims == null) {
            throw RuntimeException("Claims cannot be null for token: $token")
        }
        return claims
    }
}