package kan9hee.nolaejui_auth.entity

import lombok.Getter
import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash

@Getter
@RedisHash(value = "refreshToken", timeToLive = 86400)
class RefreshToken(
    @Id
    val refreshTokenValue:String,
    val userID:String
)