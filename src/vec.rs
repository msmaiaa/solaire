#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }

    pub fn normalize_csgo(&mut self) {
        while self.y < -180. {
            self.y += 360.;
        }
        while self.y > 180. {
            self.y -= 360.;
        }
        if self.x > 89. {
            self.x = 89.;
        }
        if self.x < -89. {
            self.x = -89.;
        }
        self.z = 0.;
    }

    pub fn to_vec_squared(&self) -> Self {
        Self {
            x: self.x.sqrt(),
            y: self.y.sqrt(),
            z: self.z.sqrt(),
        }
    }

    pub fn length(&self) -> f32 {
        (self.x * self.x + self.y * self.y + self.z * self.z).sqrt()
    }

    pub fn distance_from(&self, other: &Self) -> f32 {
        (*self - *other).length()
    }
}

impl std::ops::Add for Vec3 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            x: self.x + rhs.x,
            y: self.y + rhs.y,
            z: self.z + rhs.z,
        }
    }
}

impl std::ops::AddAssign for Vec3 {
    fn add_assign(&mut self, rhs: Self) {
        self.x += rhs.x;
        self.y += rhs.y;
        self.z += rhs.z;
    }
}

impl std::ops::Sub for Vec3 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            x: self.x - rhs.x,
            y: self.y - rhs.y,
            z: self.z - rhs.z,
        }
    }
}

impl std::ops::SubAssign for Vec3 {
    fn sub_assign(&mut self, rhs: Self) {
        self.x -= rhs.x;
        self.y -= rhs.y;
        self.z -= rhs.z;
    }
}

impl std::ops::Mul<f32> for Vec3 {
    type Output = Self;

    fn mul(self, rhs: f32) -> Self::Output {
        Self {
            x: self.x * rhs,
            y: self.y * rhs,
            z: self.z * rhs,
        }
    }
}

impl std::ops::MulAssign<f32> for Vec3 {
    fn mul_assign(&mut self, rhs: f32) {
        self.x *= rhs;
        self.y *= rhs;
        self.z *= rhs;
    }
}

impl std::ops::Div<f32> for Vec3 {
    type Output = Self;

    fn div(self, rhs: f32) -> Self::Output {
        Self {
            x: self.x / rhs,
            y: self.y / rhs,
            z: self.z / rhs,
        }
    }
}

impl std::ops::DivAssign<f32> for Vec3 {
    fn div_assign(&mut self, rhs: f32) {
        self.x /= rhs;
        self.y /= rhs;
        self.z /= rhs;
    }
}

pub struct Vec4 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub w: f32,
}

impl Vec4 {
    pub fn new(x: f32, y: f32, z: f32, w: f32) -> Self {
        Self { x, y, z, w }
    }
}

#[cfg(test)]
mod test {
    use crate::{vec::Vec4, Vec3};

    #[test]
    fn vec3_sanity_check() {
        let vec = Vec3::new(1., 2., 3.);
        assert_eq!(vec.x, 1.);
        assert_eq!(vec.y, 2.);
        assert_eq!(vec.z, 3.);
    }

    #[test]
    fn vec4_sanity_check() {
        let vec = Vec4::new(1., 2., 3., 4.);
        assert_eq!(vec.x, 1.);
        assert_eq!(vec.y, 2.);
        assert_eq!(vec.z, 3.);
        assert_eq!(vec.w, 4.);
    }

    #[test]
    fn normalize_csgo() {
        let mut vec = Vec3::new(999., 999., 999.);
        vec.normalize_csgo();
        assert_eq!(vec.x, 89.0);
        assert_eq!(vec.y, -81.0);
        assert_eq!(vec.z, 0.0);

        let mut vec2 = Vec3::new(-999., -999., -999.);
        vec2.normalize_csgo();
        assert_eq!(vec2.x, -89.0);
        assert_eq!(vec2.y, 81.0);
        assert_eq!(vec2.z, 0.0);
    }
}
