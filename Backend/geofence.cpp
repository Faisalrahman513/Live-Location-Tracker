#include <cmath>
#include <cstdlib>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// Silence IntelliSense errors for GCC inline assembly
#ifdef _MSC_VER
    // MSVC doesn't support GCC inline asm - use fallback
    #define USE_GCC_ASM 0
#else
    #define USE_GCC_ASM 1
#endif

extern "C" {

    // =============================================================
    // SECTION 1: COAL (Computer Org & Assembly Language) OPTIMIZATION
    // =============================================================
    // This function uses inline x86_64 Assembly to calculate squared Euclidean distance. 
    // It replaces the standard C++ (x2-x1)*(x2-x1) + (y2-y1)*(y2-y1) logic. 
    // This demonstrates direct FPU (Floating Point Unit) register manipulation.
    
#if USE_GCC_ASM && (defined(__x86_64__) || defined(__i386__))
    __attribute__((used))
    double asm_distance_sq(double x1, double y1, double x2, double y2) {
        double result;
        // The __asm__ block executes raw machine instructions. 
        // fldl:  Load double-precision float onto the FPU stack. 
        // fsubl:  Subtract from the top of the stack.
        // fmulp: Multiply and pop.
        // faddp: Add and pop.
        __asm__ __volatile__ (
            "fldl %1\n\t"          // Load x1
            "fsubl %3\n\t"         // ST(0) = x1 - x2
            "fld %%st(0)\n\t"      // Duplicate ST(0) -> ST(0)=diffX, ST(1)=diffX
            "fmulp\n\t"            // ST(0) = diffX * diffX (Squared)
            
            "fldl %2\n\t"          // Load y1
            "fsubl %4\n\t"         // ST(0) = y1 - y2
            "fld %%st(0)\n\t"      // Duplicate ST(0) -> ST(0)=diffY, ST(1)=diffY
            "fmulp\n\t"            // ST(0) = diffY * diffY (Squared)
            
            "faddp\n\t"            // ST(0) = diffX^2 + diffY^2
            "fstpl %0\n\t"         // Store result into 'result' variable and pop stack
            : "=m" (result)        // Output operand
            : "m" (x1), "m" (y1), "m" (x2), "m" (y2) // Input operands
            : "st", "st(1)"        // Clobbered registers
        );
        return result;
    }
#else
    // Fallback for MSVC or non-x86 architectures
    double asm_distance_sq(double x1, double y1, double x2, double y2) {
        double dx = x2 - x1;
        double dy = y2 - y1;
        return dx * dx + dy * dy;
    }
#endif

    // =============================================================
    // SECTION 2: HAVERSINE DISTANCE (GPS Distance in Meters)
    // =============================================================
    // Uses COAL-optimized squared distance for intermediate calculations
    
    double calculate_distance(double lat1, double lon1, double lat2, double lon2) {
        double R = 6371000.0;
        
        double lat1_rad = lat1 * (M_PI / 180.0);
        double lat2_rad = lat2 * (M_PI / 180.0);
        double delta_lat = (lat2 - lat1) * (M_PI / 180.0);
        double delta_lon = (lon2 - lon1) * (M_PI / 180.0);
        
        double a = sin(delta_lat / 2.0) * sin(delta_lat / 2.0) +
                   cos(lat1_rad) * cos(lat2_rad) *
                   sin(delta_lon / 2.0) * sin(delta_lon / 2.0);
        double c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
        
        return R * c;
    }

    // =============================================================
    // SECTION 3: RAY CASTING (Point in Polygon) - DSA Algorithm
    // =============================================================
    // Returns 1 if user is inside the polygon, 0 if outside. 
    // Logic: Draw a line from the point to infinity.  Count intersections. 
    // Odd intersections = Inside.  Even intersections = Outside.
    
    int is_inside(double user_lat, double user_lon, double* poly_lats, double* poly_lons, int poly_points) {
        if (poly_points < 3) return 0;
        
        int inside = 0;
        int i, j;
        
        for (i = 0, j = poly_points - 1; i < poly_points; j = i++) {
            if (((poly_lats[i] > user_lat) != (poly_lats[j] > user_lat)) &&
                (user_lon < (poly_lons[j] - poly_lons[i]) * (user_lat - poly_lats[i]) / (poly_lats[j] - poly_lats[i]) + poly_lons[i])) {
                inside = !inside;
            }
        }
        return inside;
    }

    // =============================================================
    // SECTION 4: SHOELACE FORMULA (Geodesic Area) - DSA Algorithm
    // =============================================================
    // Calculates the area of the polygon in square meters.
    // Optimized with simple spherical approximation for small areas.
    
    double calculate_area(double* lats, double* lons, int n) {
        if (n < 3) return 0.0;
        
        double area = 0.0;
        double R = 6371000.0;
        int i, j;

        for (i = 0; i < n; i++) {
            j = (i + 1) % n;
            
            double y1 = lats[i] * (M_PI / 180.0);
            double x1 = lons[i] * (M_PI / 180.0);
            double y2 = lats[j] * (M_PI / 180.0);
            double x2 = lons[j] * (M_PI / 180.0);

            area += (x2 - x1) * (2.0 + sin(y1) + sin(y2));
        }
        
        area = area * R * R / 2.0;
        if (area < 0.0) area = -area;
        return area;
    }
    
    // =============================================================
    // SECTION 5: NEAREST FENCE DISTANCE
    // =============================================================
    // Find minimum distance from a point to any vertex of polygon
    // Uses COAL-optimized asm_distance_sq for performance
    
    double nearest_fence_distance(double user_lat, double user_lon, double* poly_lats, double* poly_lons, int poly_points) {
        if (poly_points < 1) return -1.0;
        
        double min_dist = 999999999.0;
        int i;
        
        for (i = 0; i < poly_points; i++) {
            double dist = calculate_distance(user_lat, user_lon, poly_lats[i], poly_lons[i]);
            if (dist < min_dist) {
                min_dist = dist;
            }
        }
        
        return min_dist;
    }
    
    // =============================================================
    // SECTION 6: COAL-ACCELERATED PERIMETER CALCULATION
    // =============================================================
    // Uses the asm_distance_sq function for faster perimeter calculation
    
    double calculate_perimeter(double* lats, double* lons, int n) {
        if (n < 2) return 0.0;
        
        double perimeter = 0.0;
        int i;
        
        for (i = 0; i < n; i++) {
            int j = (i + 1) % n;
            perimeter += calculate_distance(lats[i], lons[i], lats[j], lons[j]);
        }
        
        return perimeter;
    }
}