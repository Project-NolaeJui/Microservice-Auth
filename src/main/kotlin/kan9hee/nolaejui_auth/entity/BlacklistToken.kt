package kan9hee.nolaejui_auth.entity

import lombok.Getter
import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash

@Getter
@RedisHash(value = "blacklistToken", timeToLive = 86400)
class BlacklistToken(
    @Id
    val tokenValue:String,
    val createdAt:Long=System.currentTimeMillis()
)