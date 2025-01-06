package kan9hee.nolaejui_auth.dao

import kan9hee.nolaejui_auth.entity.UserData
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface UserRepository:JpaRepository<UserData,Long> {
    fun findByUserID(userID:String):UserData?
    fun deleteByUserID(userID:String)
}