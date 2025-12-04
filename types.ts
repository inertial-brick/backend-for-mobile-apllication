export interface Route {
  id: number;
  name: string;
  description: string;
  duration: string;
  distance: string;
  images: string[];
}

export interface UserWithRoutes {
  id: number;
  name: string;
  about: string;
  email: string;
  profile_image: string;
  routes: Route[];
}

export interface UserBasic {
  id: number;
  name: string;
  email: string;
  about: string;
  profile_image: string;
}
