package kan9hee.nolaejui_auth.dao

import kan9hee.nolaejui_auth.entity.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface UserRepository:JpaRepository<User,Long> {
    fun findUsername(userID:String):User
}